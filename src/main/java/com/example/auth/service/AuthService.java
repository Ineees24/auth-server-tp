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

/**
 * Service principal de gestion de l'authentification.
 * TP4 : les mots de passe sont chiffrés via AES-GCM avec une Master Key.
 * TP3 : protocole HMAC + nonce + timestamp. Le mot de passe ne circule plus.
 *
 * AVERTISSEMENT : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
@Service
public class AuthService {

    private static final Logger logger =
            LoggerFactory.getLogger(AuthService.class);

    private static final int  TIMESTAMP_WINDOW = 60;
    private static final int  TOKEN_DURATION   = 15;
    private static final long NONCE_TTL        = 120;

    private final UserRepository        userRepository;
    private final AuthNonceRepository   nonceRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final HmacService           hmacService;
    private final TokenService          tokenService;
    private final MasterKeyService      masterKeyService;

    public AuthService(UserRepository userRepository,
                       AuthNonceRepository nonceRepository,
                       BCryptPasswordEncoder passwordEncoder,
                       HmacService hmacService,
                       TokenService tokenService,
                       MasterKeyService masterKeyService) {
        this.userRepository   = userRepository;
        this.nonceRepository  = nonceRepository;
        this.passwordEncoder  = passwordEncoder;
        this.hmacService      = hmacService;
        this.tokenService     = tokenService;
        this.masterKeyService = masterKeyService;
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

        // Hash BCrypt puis chiffrement AES-GCM
        String hashedPassword;
        try {
            String bcryptHash = passwordEncoder.encode(password);
            hashedPassword    = masterKeyService.encrypt(bcryptHash);
        } catch (Exception e) {
            logger.error("Erreur chiffrement mot de passe");
            throw new InvalidInputException("Erreur lors de l'inscription");
        }

        User user  = new User(email, hashedPassword);
        User saved = userRepository.save(user);
        logger.info("Inscription reussie");
        return saved;
    }

    // ── Connexion HMAC ────────────────────────────────────────────────────────
    /**
     * Vérifie la preuve HMAC envoyée par le client.
     * TP4 : déchiffre le mot de passe via Master Key avant vérification HMAC.
     * Ordre des vérifications :
     * 1. Email existe
     * 2. Timestamp dans fenêtre ±60s
     * 3. Nonce non utilisé
     * 4. Déchiffrement du mot de passe
     * 5. HMAC valide en temps constant
     * 6. Émettre token SSO
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

        // 4. Enregistrer le nonce
        AuthNonce authNonce = new AuthNonce(
                user, nonce,
                LocalDateTime.now().plusSeconds(NONCE_TTL)
        );
        nonceRepository.save(authNonce);

        // 5. Déchiffrer le mot de passe stocké
        try {
            String storedPassword = masterKeyService.decrypt(user.getPassword());

            // 6. Recalculer le HMAC attendu
            String message      = email + ":" + nonce + ":" + timestamp;
            String hmacExpected = hmacService.compute(storedPassword, message);

            // 7. Comparer en temps constant
            if (!hmacService.compareConstantTime(hmacExpected, hmac)) {
                logger.warn("Login refuse: HMAC invalide");
                throw new AuthenticationFailedException("Authentification echouee");
            }

        } catch (AuthenticationFailedException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Erreur calcul HMAC ou dechiffrement");
            throw new AuthenticationFailedException("Authentification echouee");
        }

        // 8. Marquer nonce comme consommé
        nonceRepository.findByUserAndNonce(user, nonce)
                .ifPresent(n -> {
                    n.setConsumed(true);
                    nonceRepository.save(n);
                });

        // 9. Émettre token SSO
        String        accessToken = tokenService.generateToken(email);
        LocalDateTime expiresAt   = LocalDateTime.now().plusMinutes(TOKEN_DURATION);

        logger.info("Connexion reussie");
        return new SsoToken(accessToken, expiresAt);
    }

    // ── Helpers pour les tests ────────────────────────────────────────────────

    /** Récupère un utilisateur par email — utilisé pour les tests */
    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new AuthenticationFailedException("User not found"));
    }

    /** Valide un token — utilisé pour les tests */
    public String validateToken(String token) {
        if (token == null) {
            throw new AuthenticationFailedException("Token manquant");
        }
        return tokenService.getEmailFromToken(token)
                .orElseThrow(() ->
                        new AuthenticationFailedException("Token invalide"));
    }
    /**
     * Change le mot de passe d'un utilisateur authentifié.
     * TP5 : vérifie l'ancien mot de passe, la confirmation et la politique.
     *
     * Étapes :
     * 1. Vérifier que l'utilisateur existe
     * 2. Vérifier que l'ancien mot de passe est correct
     * 3. Vérifier que newPassword = confirmPassword
     * 4. Vérifier la politique du nouveau mot de passe
     * 5. Chiffrer et stocker le nouveau mot de passe
     */
    public void changePassword(String email, String oldPassword,
                               String newPassword, String confirmPassword) {

        // 1. Vérifier que l'utilisateur existe
        User user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new AuthenticationFailedException("Utilisateur introuvable"));

        // 2. Vérifier l'ancien mot de passe
        try {
            String storedDecrypted = masterKeyService.decrypt(user.getPassword());
            if (!passwordEncoder.matches(oldPassword, storedDecrypted)) {
                logger.warn("Changement mot de passe refuse: ancien mot de passe incorrect");
                throw new AuthenticationFailedException("Ancien mot de passe incorrect");
            }
        } catch (AuthenticationFailedException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Erreur dechiffrement lors du changement de mot de passe");
            throw new AuthenticationFailedException("Erreur lors de la verification");
        }

        // 3. Vérifier que newPassword = confirmPassword
        if (!newPassword.equals(confirmPassword)) {
            throw new InvalidInputException(
                    "Le nouveau mot de passe et la confirmation ne correspondent pas");
        }

        // 4. Vérifier la politique du nouveau mot de passe
        PasswordPolicyValidator.validate(newPassword);

        // 5. Chiffrer et stocker le nouveau mot de passe
        try {
            String newBcrypt    = passwordEncoder.encode(newPassword);
            String newEncrypted = masterKeyService.encrypt(newBcrypt);
            user.setPassword(newEncrypted);
            userRepository.save(user);
            logger.info("Mot de passe change avec succes");
        } catch (Exception e) {
            logger.error("Erreur chiffrement nouveau mot de passe");
            throw new InvalidInputException("Erreur lors du changement de mot de passe");
        }
    }
}