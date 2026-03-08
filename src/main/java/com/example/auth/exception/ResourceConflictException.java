package com.example.auth.exception;

/**
 * Exception levée quand une ressource existe déjà (ex: email dupliqué).
 * Cette implémentation est volontairement dangereuse et ne doit jamais
 * être utilisée en production.
 */
public class ResourceConflictException extends RuntimeException {
    public ResourceConflictException(String message) {
        super(message);
    }
}