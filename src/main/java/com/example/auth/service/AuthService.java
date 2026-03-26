package com.example.auth.service;

import com.example.auth.entity.AuthNonce;
import com.example.auth.entity.SsoToken;
import com.example.auth.entity.User;
import com.example.auth.exception.*;
import com.example.auth.repository.AuthNonceRepository;
import com.example.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Service principal de gestion de l'authentification.
 * TP3 : protocole HMAC + nonce + timestamp. Le mot de passe ne circule plus.
 * TP2 améliore le stockage mais ne protège pas encore contre le rejeu.
 *
 * AVERTISSEMENT : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
@Service
public class AuthService {

    private static final Logger logger =
            LoggerFactory.getLogger(AuthService.class);

    private static final int    TIMESTAMP_WINDOW = 60;   // ±60 secondes
    private static final int    TOKEN_DURATION   = 15;   // 15 minutes
    private static final long   NONCE_TTL        = 120;  // 2 minutes

    private final UserRepository     userRepository;
    private final AuthNonceRepository nonceRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final HmacService         hmacService;
    private final TokenService        tokenService;

    public AuthService(UserRepository userRepository,
                       AuthNonceRepository nonceRepository,
                       BCryptPasswordEncoder passwordEncoder,
                       HmacService hmacService,
                       TokenService tokenService) {
        this.userRepository  = userRepository;
        this.nonceRepository = nonceRepository;
        this.passwordEncoder = passwordEncoder;
        this.hmacService     = hmacService;
        this.tokenService    = tokenService;
    }

    // ── Inscription ───────────────────────────────────────────────────────────
    public User register(String email, String password) {
        if (email == null || email.isBlank() || !email.contains("@")) {
            logger.warn("Inscription echouee: email invalide");
            throw new InvalidInputException("Email invalide");
        }

        PasswordPolicyValidator.validate(password);

        if (userRepository.findByEmail(email).isPresent()) {
            logger.warn("Inscription echouee: email deja existant");
            throw new ResourceConflictException("Email deja utilise");
        }

        String hashedPassword = passwordEncoder.encode(password);
        User user = new User(email, hashedPassword);
        User saved = userRepository.save(user);
        logger.info("Inscription reussie");
        return saved;
    }

    // ── Connexion HMAC ────────────────────────────────────────────────────────
    /**
     * Vérifie la preuve HMAC envoyée par le client.
     * Ordre des vérifications obligatoire :
     * 1. Email existe
     * 2. Timestamp dans la fenêtre ±60s
     * 3. Nonce non déjà utilisé
     * 4. HMAC valide en temps constant
     * 5. Émettre token SSO
     */
    public SsoToken login(String email, String nonce,
                          long timestamp, String hmac) {
        // 1. Vérifier email
        User user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new AuthenticationFailedException("Authentification echouee"));

        // 2. Vérifier timestamp ±60 secondes
        long now = Instant.now().getEpochSecond();
        if (Math.abs(now - timestamp) > TIMESTAMP_WINDOW) {
            logger.warn("Login refuse: timestamp expire");
            throw new AuthenticationFailedException("Authentification echouee");
        }

        // 3. Vérifier nonce anti-rejeu
        nonceRepository.findByUserAndNonce(user, nonce).ifPresent(n -> {
            logger.warn("Login refuse: nonce deja utilise");
            throw new AuthenticationFailedException("Authentification echouee");
        });

        // 4. Enregistrer le nonce pour bloquer tout rejeu futur
        AuthNonce authNonce = new AuthNonce(
                user, nonce,
                LocalDateTime.now().plusSeconds(NONCE_TTL)
        );
        nonceRepository.save(authNonce);

        // 5. Recalculer le HMAC attendu
        try {
            // Le mot de passe stocké en base est haché (BCrypt)
            // On ne peut pas l'utiliser directement comme clé HMAC
            // TP3 pédagogique : on utilise le hash BCrypt comme clé
            String message      = email + ":" + nonce + ":" + timestamp;
            String hmacExpected = hmacService.compute(
                    user.getPassword(), message);

            // 6. Comparer en temps constant
            if (!hmacService.compareConstantTime(hmacExpected, hmac)) {
                logger.warn("Login refuse: HMAC invalide");
                throw new AuthenticationFailedException("Authentification echouee");
            }

        } catch (AuthenticationFailedException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Erreur calcul HMAC");
            throw new AuthenticationFailedException("Authentification echouee");
        }

        // 7. Marquer nonce comme consommé
        nonceRepository.findByUserAndNonce(user, nonce)
                .ifPresent(n -> {
                    n.setConsumed(true);
                    nonceRepository.save(n);
                });

        // 8. Émettre token SSO
        String accessToken = tokenService.generateToken(email);
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(TOKEN_DURATION);

        logger.info("Connexion reussie");
        return new SsoToken(accessToken, expiresAt);
    }
}