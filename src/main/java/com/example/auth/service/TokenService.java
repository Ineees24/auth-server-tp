package com.example.auth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import java.util.*;

@Service
public class TokenService {

    private static final Logger logger = LoggerFactory.getLogger(TokenService.class);
    private final Map<String, String> tokens = new HashMap<>();

    public String generateToken(String email) {
        String token = UUID.randomUUID().toString();
        tokens.put(token, email);
        logger.info("Token genere");
        return token;
    }

    public Optional<String> getEmailFromToken(String token) {
        return Optional.ofNullable(tokens.get(token));
    }

    public boolean isValidToken(String token) {
        return token != null && tokens.containsKey(token);
    }
}