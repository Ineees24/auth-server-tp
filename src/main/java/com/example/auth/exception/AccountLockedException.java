package com.example.auth.exception;

/**
 * Exception levée quand le compte est temporairement bloqué.
 * TP2 : blocage après 5 échecs pendant 2 minutes.
 *
 * AVERTISSEMENT : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
public class AccountLockedException extends RuntimeException {
    public AccountLockedException(String message) {
        super(message);
    }
}