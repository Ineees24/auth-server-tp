package com.example.auth.controller;

import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.service.AuthService;
import com.example.auth.service.TokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

/**
 * Controller REST exposant les endpoints d'authentification.
 * Cette implémentation est volontairement dangereuse et ne doit jamais
 * être utilisée en production.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final TokenService tokenService;

    public AuthController(AuthService authService, TokenService tokenService) {
        this.authService = authService;
        this.tokenService = tokenService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestParam String email,
                                      @RequestParam String password) {
        authService.register(email, password);
        return ResponseEntity.ok(Map.of("message", "Inscription reussie"));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String email,
                                   @RequestParam String password) {
        boolean ok = authService.login(email, password);
        if (!ok) {
            throw new AuthenticationFailedException("Email ou mot de passe incorrect");
        }
        String token = tokenService.generateToken(email);
        return ResponseEntity.ok(Map.of(
                "message", "Connexion reussie",
                "token", token
        ));
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new AuthenticationFailedException("Token manquant");
        }
        String token = authHeader.substring(7);
        return tokenService.getEmailFromToken(token)
                .map(email -> ResponseEntity.ok(Map.of("email", email)))
                .orElseThrow(() -> new AuthenticationFailedException("Token invalide"));
    }
}