package com.example.auth.service;

import com.example.auth.entity.User;
import com.example.auth.exception.*;
import com.example.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
/**
 * Service principal de gestion de l'authentification.
 * TP2 améliore le stockage mais ne protège pas encore contre le rejeu.
 *
 * AVERTISSEMENT : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository,
                       BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public User register(String email, String password) {
        // Validation email
        if (email == null || email.isBlank() || !email.contains("@")) {
            logger.warn("Inscription echouee: email invalide");
            throw new InvalidInputException("Email invalide");
        }

        // Validation politique mot de passe
        PasswordPolicyValidator.validate(password);

        // Vérifier unicité email
        if (userRepository.findByEmail(email).isPresent()) {
            logger.warn("Inscription echouee: email deja existant {}", email);
            throw new ResourceConflictException("Email deja utilise");
        }

        // Hash du mot de passe avant stockage
        String hashedPassword = passwordEncoder.encode(password);
        User user = new User(email, hashedPassword);
        User saved = userRepository.save(user);
        logger.info("Inscription reussie pour : {}", email);
        return saved;
    }

    public boolean login(String email, String password) {
        if (email == null || password == null) {
            throw new InvalidInputException("Email et mot de passe requis");
        }

        User user = userRepository.findByEmail(email).orElse(null);

        // Email inconnu : on retourne false sans info supplémentaire
        if (user == null) {
            logger.warn("Connexion echouee: email inconnu {}", email);
            return false;
        }

        // Vérifier si le compte est bloqué
        if (user.getLockUntil() != null &&
                user.getLockUntil().isAfter(LocalDateTime.now())) {
            logger.warn("Connexion refusee: compte bloque pour {}", email);
            throw new AccountLockedException(
                    "Compte bloque. Reessayez dans 2 minutes.");
        }

        // Vérifier le mot de passe
        boolean success = passwordEncoder.matches(password, user.getPassword());

        if (success) {
            // Réinitialiser les compteurs en cas de succès
            user.setFailedAttempts(0);
            user.setLockUntil(null);
            userRepository.save(user);
            logger.info("Connexion reussie pour : {}", email);
        } else {
            // Incrémenter le compteur d'échecs
            int attempts = user.getFailedAttempts() + 1;
            user.setFailedAttempts(attempts);

            if (attempts >= 5) {
                // Bloquer le compte 2 minutes
                user.setLockUntil(LocalDateTime.now().plusMinutes(2));
                userRepository.save(user);
                logger.warn("Compte bloque apres 5 echecs pour : {}", email);
                throw new AccountLockedException(
                        "Compte bloque apres 5 echecs. Reessayez dans 2 minutes.");
            }

            userRepository.save(user);
            logger.warn("Connexion echouee ({}/5) pour : {}", attempts, email);
        }

        return success;
    }
}