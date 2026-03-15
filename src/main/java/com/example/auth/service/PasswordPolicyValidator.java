package com.example.auth.service;

import com.example.auth.exception.InvalidInputException;

/**
 * Validateur de politique de mot de passe.
 * TP2 : politique stricte (12 caractères min, maj, min, chiffre, spécial).
 *
 * AVERTISSEMENT : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
public class PasswordPolicyValidator {

    private static final int MIN_LENGTH = 12;

    /**
     * Valide le mot de passe selon la politique TP2.
     * @throws InvalidInputException si le mot de passe ne respecte pas les règles
     */
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
        if (!password.matches(".*[0-9].*")) {
            throw new InvalidInputException(
                    "Mot de passe doit contenir au moins un chiffre");
        }
        if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*")) {
            throw new InvalidInputException(
                    "Mot de passe doit contenir au moins un caractère spécial");
        }
    }
}