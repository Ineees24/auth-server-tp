package com.example.auth.service;

import com.example.auth.entity.User;
import com.example.auth.exception.*;
import com.example.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Service principal de gestion de l'authentification.
 *
 * AVERTISSEMENT : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 * Les mots de passe sont stockés et comparés en clair.
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private final UserRepository userRepository;

    public AuthService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User register(String email, String password) {
        if (email == null || email.isBlank() || !email.contains("@")) {
            logger.warn("Inscription echouee: email invalide");
            throw new InvalidInputException("Email invalide");
        }
        if (password == null || password.length() < 4) {
            logger.warn("Inscription echouee: mot de passe trop court");
            throw new InvalidInputException("Mot de passe trop court (min 4 caracteres)");
        }
        if (userRepository.findByEmail(email).isPresent()) {
            logger.warn("Inscription echouee: email deja existant {}", email);
            throw new ResourceConflictException("Email deja utilise");
        }
        User user = new User(email, password);
        User saved = userRepository.save(user);
        logger.info("Inscription reussie pour : {}", email);
        return saved;
    }

    public boolean login(String email, String password) {
        if (email == null || password == null) {
            throw new InvalidInputException("Email et mot de passe requis");
        }
        boolean success = userRepository.findByEmail(email)
                .map(user -> user.getPassword().equals(password))
                .orElse(false);
        if (success) {
            logger.info("Connexion reussie pour : {}", email);
        } else {
            logger.warn("Connexion echouee pour : {}", email);
        }
        return success;
    }
}