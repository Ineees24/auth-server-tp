package com.example.auth.service;

import org.springframework.stereotype.Service;
import java.util.*;

/**
 * Service de gestion des tokens d'authentification.
 * Cette implémentation est volontairement dangereuse et ne doit jamais
 * être utilisée en production.
 */
@Service
public class TokenService {

    // Stockage en mémoire - TP1 uniquement
    private final Map<String, String> tokens = new HashMap<>();

    public String generateToken(String email) {
        String token = UUID.randomUUID().toString();
        tokens.put(token, email);
        return token;
    }

    public Optional<String> getEmailFromToken(String token) {
        return Optional.ofNullable(tokens.get(token));
    }

    public boolean isValidToken(String token) {
        return token != null && tokens.containsKey(token);
    }
}