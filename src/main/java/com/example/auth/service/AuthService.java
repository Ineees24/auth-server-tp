package com.example.auth.service;

import com.example.auth.entity.User;
import com.example.auth.exception.*;
import com.example.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

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

        boolean success = userRepository.findByEmail(email)
                .map(user -> passwordEncoder.matches(password, user.getPassword()))
                .orElse(false);

        if (success) {
            logger.info("Connexion reussie pour : {}", email);
        } else {
            logger.warn("Connexion echouee pour : {}", email);
        }
        return success;
    }
}