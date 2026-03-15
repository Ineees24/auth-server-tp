package com.example.auth.service;

import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class TokenService {

    private final Map<String, String> tokens = new ConcurrentHashMap<>();

    public String generateToken(String email) {
        String token = UUID.randomUUID().toString();
        tokens.put(token, email);
        System.out.println("Token généré: " + token);
        System.out.println("Tokens en mémoire: " + tokens);
        return token;
    }

    public Optional<String> getEmailFromToken(String token) {
        System.out.println("Token reçu: '" + token + "'");
        System.out.println("Tokens en mémoire: " + tokens);
        return Optional.ofNullable(tokens.get(token));
    }

    public boolean isValidToken(String token) {
        return token != null && tokens.containsKey(token);
    }
}