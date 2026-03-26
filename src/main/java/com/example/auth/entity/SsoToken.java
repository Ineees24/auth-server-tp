package com.example.auth.entity;

import java.time.LocalDateTime;

/**
 * DTO représentant le token SSO retourné après authentification.
 * TP3 : accessToken + expiresAt.
 *
 * AVERTISSEMENT : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
public class SsoToken {

    private String        accessToken;
    private LocalDateTime expiresAt;

    public SsoToken(String accessToken, LocalDateTime expiresAt) {
        this.accessToken = accessToken;
        this.expiresAt   = expiresAt;
    }

    public String        getAccessToken() { return accessToken; }
    public LocalDateTime getExpiresAt()   { return expiresAt; }
}