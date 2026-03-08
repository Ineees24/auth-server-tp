package com.example.auth.exception;

/**
 * Exception levée quand les données envoyées par le client sont invalides.
 * Cette implémentation est volontairement dangereuse et ne doit jamais
 * être utilisée en production.
 */
public class InvalidInputException extends RuntimeException {
    public InvalidInputException(String message) {
        super(message);
    }
}