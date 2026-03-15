package com.example.authclient.service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Service gérant tous les appels HTTP vers le backend Spring Boot.
 * URL de base : http://localhost:8080/api/auth
 *
 * AVERTISSEMENT : Ce service communique avec une API volontairement
 * dangereuse (TP1). Ne jamais utiliser en production.
 */
public class AuthService {

    private static final String BASE_URL = "http://localhost:8080/api/auth";

    private static final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    // Token Bearer stocké en mémoire après connexion
    private static String token = null;
    private static String email = null;

    // ── Getters session ───────────────────────────────────────────────────────

    public static String getToken()  { return token; }
    public static String getEmail()  { return email; }
    public static boolean isLoggedIn() { return token != null; }

    public static void logout() {
        token = null;
        email = null;
    }

    // ── Réponse HTTP interne ──────────────────────────────────────────────────

    public static class ApiResponse {
        public final int status;
        public final String body;

        public ApiResponse(int status, String body) {
            this.status = status;
            this.body   = body;
        }

        public boolean isSuccess() {
            return status >= 200 && status < 300;
        }
    }

    // ── Inscription : POST /api/auth/register ─────────────────────────────────

    /**
     * Inscrit un nouvel utilisateur.
     * @param userEmail    l'email saisi
     * @param userPassword le mot de passe saisi
     * @return ApiResponse avec status HTTP et body JSON
     */
    public static ApiResponse register(String userEmail, String userPassword) {
        String body = "email=" + encode(userEmail) + "&password=" + encode(userPassword);
        return post("/register", body);
    }

    // ── Connexion : POST /api/auth/login ──────────────────────────────────────

    /**
     * Connecte l'utilisateur et stocke le token en mémoire si succès.
     * @param userEmail    l'email saisi
     * @param userPassword le mot de passe saisi
     * @return ApiResponse avec status HTTP et body JSON
     */
    public static ApiResponse login(String userEmail, String userPassword) {
        String body = "email=" + encode(userEmail) + "&password=" + encode(userPassword);
        ApiResponse response = post("/login", body);

        if (response.isSuccess()) {
            // Extraire le token de la réponse JSON
            String extractedToken = extractJson(response.body, "token");
            if (extractedToken != null) {
                token = extractedToken;
                email = userEmail;
            }
        }
        return response;
    }

    // ── Profil : GET /api/auth/me ─────────────────────────────────────────────

    /**
     * Récupère le profil de l'utilisateur connecté.
     * Envoie le token Bearer dans le header Authorization.
     * @return ApiResponse avec status HTTP et body JSON
     */
    public static ApiResponse getMe() {
        if (token == null) {
            return new ApiResponse(401, "{\"message\":\"Non connecté\"}");
        }
        return get("/me", token);
    }

    // ── Méthodes HTTP privées ─────────────────────────────────────────────────

    private static ApiResponse post(String endpoint, String formData) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(BASE_URL + endpoint))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(formData))
                    .timeout(Duration.ofSeconds(5))
                    .build();

            HttpResponse<String> response =
                    httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return new ApiResponse(response.statusCode(), response.body());

        } catch (Exception e) {
            return new ApiResponse(0, "Serveur inaccessible : " + e.getMessage());
        }
    }

    private static ApiResponse get(String endpoint, String bearerToken) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(BASE_URL + endpoint))
                    .header("Authorization", "Bearer " + bearerToken)
                    .GET()
                    .timeout(Duration.ofSeconds(5))
                    .build();

            HttpResponse<String> response =
                    httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return new ApiResponse(response.statusCode(), response.body());

        } catch (Exception e) {
            return new ApiResponse(0, "Serveur inaccessible : " + e.getMessage());
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /** Extraction simple d'une valeur dans un JSON à plat. */
    public static String extractJson(String json, String key) {
        String search = "\"" + key + "\":\"";
        int start = json.indexOf(search);
        if (start == -1) return null;
        start += search.length();
        int end = json.indexOf("\"", start);
        if (end == -1) return null;
        return json.substring(start, end);
    }
}