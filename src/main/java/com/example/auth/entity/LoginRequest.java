package com.example.auth.entity;

/**
 * DTO représentant la requête de login TP3.
 * Contient email, nonce, timestamp et hmac — pas le mot de passe !
 *
 * AVERTISSEMENT : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
public class LoginRequest {

    private String email;
    private String nonce;
    private long   timestamp;
    private String hmac;

    public LoginRequest() {}

    public String getEmail()     { return email; }
    public String getNonce()     { return nonce; }
    public long   getTimestamp() { return timestamp; }
    public String getHmac()      { return hmac; }

    public void setEmail(String email)         { this.email = email; }
    public void setNonce(String nonce)         { this.nonce = nonce; }
    public void setTimestamp(long timestamp)   { this.timestamp = timestamp; }
    public void setHmac(String hmac)           { this.hmac = hmac; }
}