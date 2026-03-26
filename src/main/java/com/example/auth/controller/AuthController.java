package com.example.auth.controller;

import com.example.auth.entity.LoginRequest;
import com.example.auth.entity.SsoToken;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.service.AuthService;
import com.example.auth.service.TokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Controller REST exposant les endpoints d'authentification.
 * TP3 : le login reçoit email + nonce + timestamp + hmac.
 *
 * AVERTISSEMENT : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final String MESSAGE = "message";
    private static final String STATUS  = "status";
    private static final String ERROR   = "error";
    private static final String PATH    = "path";

    private final AuthService  authService;
    private final TokenService tokenService;

    public AuthController(AuthService authService,
                          TokenService tokenService) {
        this.authService  = authService;
        this.tokenService = tokenService;
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(
            @RequestParam String email,
            @RequestParam String password) {
        authService.register(email, password);
        return ResponseEntity.ok(Map.of(MESSAGE, "Inscription reussie"));
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @RequestParam String email,
            @RequestParam String nonce,
            @RequestParam long   timestamp,
            @RequestParam String hmac) {

        SsoToken token = authService.login(email, nonce, timestamp, hmac);

        return ResponseEntity.ok(Map.of(
                "accessToken", token.getAccessToken(),
                "expiresAt",   token.getExpiresAt().toString()
        ));
    }

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> me(
            @RequestHeader(value = "Authorization", required = false)
            String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new AuthenticationFailedException("Token manquant");
        }

        String token = authHeader.substring(7);
        return tokenService.getEmailFromToken(token)
                .map(email -> ResponseEntity.ok(
                        Map.of("email", (Object) email)))
                .orElseThrow(() ->
                        new AuthenticationFailedException("Token invalide"));
    }
}