package com.example.auth.service;

import com.example.auth.exception.InvalidInputException;

/**
 * Validateur de politique de mot de passe.
 * AVERTISSEMENT : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
public class PasswordPolicyValidator {

    // Constructeur privé pour éviter l'instanciation
    private PasswordPolicyValidator() {}

    private static final int MIN_LENGTH = 12;

    public static void validate(String password) {
        if (password == null || password.length() < MIN_LENGTH) {
            throw new InvalidInputException(
                    "Mot de passe trop court (minimum " + MIN_LENGTH + " caractères)");
        }
        if (!password.matches(".*[A-Z].*")) {
            throw new InvalidInputException(
                    "Mot de passe doit contenir au moins une majuscule");
        }
        if (!password.matches(".*[a-z].*")) {
            throw new InvalidInputException(
                    "Mot de passe doit contenir au moins une minuscule");
        }
        if (!password.matches(".*\\d.*")) {
            throw new InvalidInputException(
                    "Mot de passe doit contenir au moins un chiffre");
        }
        if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*")) {
            throw new InvalidInputException(
                    "Mot de passe doit contenir au moins un caractère spécial");
        }
    }
}