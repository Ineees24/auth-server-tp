package com.example.authclient.service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Service gérant tous les appels HTTP vers le backend Spring Boot.
 * TP3 : Le mot de passe ne circule plus — on envoie un HMAC signé.
 *
 * AVERTISSEMENT : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
public class AuthService {

    private static final String BASE_URL = "http://localhost:8080/api/auth";

    private static final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    // Session
    private static String token = null;
    private static String email = null;

    public static String getToken()      { return token; }
    public static String getEmail()      { return email; }
    public static boolean isLoggedIn()   { return token != null; }

    public static void logout() {
        token = null;
        email = null;
    }

    // ── Réponse HTTP ──────────────────────────────────────────────────────────
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
     * Inscription — le mot de passe est encore envoyé directement ici.
     * Seul le login utilise HMAC en TP3.
     */
    public static ApiResponse register(String userEmail, String userPassword) {
        String body = "email=" + encode(userEmail) + "&password=" + encode(userPassword);
        return post("/register", body);
    }

    // ── Connexion : POST /api/auth/login avec HMAC ────────────────────────────
    /**
     * Connexion TP3 : le mot de passe ne circule plus sur le réseau.
     * On envoie : email + nonce + timestamp + HMAC.
     * Le HMAC est calculé avec le mot de passe comme clé secrète.
     */
    public static ApiResponse login(String userEmail, String userPassword) {
        try {
            // 1. Générer nonce et timestamp
            String nonce     = UUID.randomUUID().toString();
            long   timestamp = Instant.now().getEpochSecond();

            // 2. Construire le message à signer
            String message = userEmail + ":" + nonce + ":" + timestamp;

            // 3. Calculer HMAC-SHA256 avec le mot de passe comme clé
            String hmac = computeHmac(userPassword, message);

            // 4. Envoyer email + nonce + timestamp + hmac (PAS le mot de passe !)
            String body = "email="     + encode(userEmail) +
                    "&nonce="     + encode(nonce) +
                    "&timestamp=" + timestamp +
                    "&hmac="      + encode(hmac);

            ApiResponse response = post("/login", body);

            if (response.isSuccess()) {
                String extractedToken = extractJson(response.body, "accessToken");
                if (extractedToken != null) {
                    token = extractedToken;
                    email = userEmail;
                }
            }
            return response;

        } catch (Exception e) {
            return new ApiResponse(0, "Erreur HMAC : " + e.getMessage());
        }
    }

    // ── Profil : GET /api/auth/me ─────────────────────────────────────────────
    public static ApiResponse getMe() {
        if (token == null) {
            return new ApiResponse(401, "{\"message\":\"Non connecté\"}");
        }
        return get("/me", token);
    }

    // ── HMAC-SHA256 ───────────────────────────────────────────────────────────
    /**
     * Calcule HMAC-SHA256(key=password, data=message).
     * Retourne le résultat en hexadécimal.
     */
    private static String computeHmac(String key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(
                key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(keySpec);
        byte[] rawHmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(rawHmac);
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