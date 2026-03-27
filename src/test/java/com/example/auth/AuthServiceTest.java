package com.example.auth;

import com.example.auth.exception.*;
import com.example.auth.entity.SsoToken;
import com.example.auth.service.AuthService;
import com.example.auth.service.HmacService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class AuthServiceTest {

    @Autowired private AuthService authService;
    @Autowired private HmacService hmacService;

    private static final String VALID_EMAIL    = "test@example.com";
    private static final String VALID_PASSWORD = "Abcdef123!@#";

    // ── Helper ────────────────────────────────────────────────────────────────

    private String computeHmac(String password, String email,
                               String nonce, long timestamp) throws Exception {
        String message = email + ":" + nonce + ":" + timestamp;
        return hmacService.compute(password, message);
    }

    private void registerUser() {
        authService.register(VALID_EMAIL, VALID_PASSWORD);
    }

    // ── Tests inscription ─────────────────────────────────────────────────────

    // Test 1
    @Test
    void testRegisterOK() {
        assertDoesNotThrow(() ->
                authService.register(VALID_EMAIL, VALID_PASSWORD));
    }

    // Test 2
    @Test
    void testRegisterEmailVide() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("", VALID_PASSWORD));
    }

    // Test 3
    @Test
    void testRegisterEmailFormatIncorrect() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("pasunmail", VALID_PASSWORD));
    }

    // Test 4
    @Test
    void testRegisterPasswordTropCourt() {
        assertThrows(InvalidInputException.class, () ->
                authService.register(VALID_EMAIL, "abc"));
    }

    // Test 5
    @Test
    void testRegisterEmailDejaExistant() {
        authService.register(VALID_EMAIL, VALID_PASSWORD);
        assertThrows(ResourceConflictException.class, () ->
                authService.register(VALID_EMAIL, VALID_PASSWORD));
    }

    // ── Tests login HMAC ──────────────────────────────────────────────────────

    // Test 6 : Login OK avec HMAC valide
    @Test
    void testLoginOKHmacValide() throws Exception {
        registerUser();

        // Récupérer le hash BCrypt stocké
        var user = authService.findByEmail(VALID_EMAIL);
        String nonce     = UUID.randomUUID().toString();
        long   timestamp = Instant.now().getEpochSecond();
        String message   = VALID_EMAIL + ":" + nonce + ":" + timestamp;
        String hmac      = hmacService.compute(user.getPassword(), message);

        SsoToken token = authService.login(VALID_EMAIL, nonce, timestamp, hmac);
        assertNotNull(token);
        assertNotNull(token.getAccessToken());
        assertNotNull(token.getExpiresAt());
    }

    // Test 7 : Login KO HMAC invalide
    @Test
    void testLoginKOHmacInvalide() {
        registerUser();
        String nonce     = UUID.randomUUID().toString();
        long   timestamp = Instant.now().getEpochSecond();

        assertThrows(AuthenticationFailedException.class, () ->
                authService.login(VALID_EMAIL, nonce, timestamp, "mauvais_hmac"));
    }

    // Test 8 : Login KO timestamp expiré
    @Test
    void testLoginKOTimestampExpire() throws Exception {
        registerUser();
        var user = authService.findByEmail(VALID_EMAIL);
        String nonce     = UUID.randomUUID().toString();
        long   timestamp = Instant.now().getEpochSecond() - 120; // 2 min dans le passé
        String message   = VALID_EMAIL + ":" + nonce + ":" + timestamp;
        String hmac      = hmacService.compute(user.getPassword(), message);

        assertThrows(AuthenticationFailedException.class, () ->
                authService.login(VALID_EMAIL, nonce, timestamp, hmac));
    }

    // Test 9 : Login KO timestamp futur
    @Test
    void testLoginKOTimestampFutur() throws Exception {
        registerUser();
        var user = authService.findByEmail(VALID_EMAIL);
        String nonce     = UUID.randomUUID().toString();
        long   timestamp = Instant.now().getEpochSecond() + 120; // 2 min dans le futur
        String message   = VALID_EMAIL + ":" + nonce + ":" + timestamp;
        String hmac      = hmacService.compute(user.getPassword(), message);

        assertThrows(AuthenticationFailedException.class, () ->
                authService.login(VALID_EMAIL, nonce, timestamp, hmac));
    }

    // Test 10 : Login KO nonce déjà utilisé (anti-rejeu)
    @Test
    void testLoginKONonceDejaUtilise() throws Exception {
        registerUser();
        var user = authService.findByEmail(VALID_EMAIL);
        String nonce     = UUID.randomUUID().toString();
        long   timestamp = Instant.now().getEpochSecond();
        String message   = VALID_EMAIL + ":" + nonce + ":" + timestamp;
        String hmac      = hmacService.compute(user.getPassword(), message);

        // Premier login OK
        authService.login(VALID_EMAIL, nonce, timestamp, hmac);

        // Deuxième login avec même nonce → doit échouer
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login(VALID_EMAIL, nonce, timestamp, hmac));
    }

    // Test 11 : Login KO email inconnu
    @Test
    void testLoginKOEmailInconnu() {
        String nonce     = UUID.randomUUID().toString();
        long   timestamp = Instant.now().getEpochSecond();

        assertThrows(AuthenticationFailedException.class, () ->
                authService.login("inconnu@test.com", nonce, timestamp, "hmac"));
    }

    // Test 12 : Comparaison temps constant
    @Test
    void testComparaisonTempsConstant() {
        String a = "abc123";
        String b = "abc123";
        String c = "different";

        assertTrue(hmacService.compareConstantTime(a, b));
        assertFalse(hmacService.compareConstantTime(a, c));
    }

    // Test 13 : Token émis et /api/me accessible
    @Test
    void testTokenEmisEtAccesMe() throws Exception {
        registerUser();
        var user = authService.findByEmail(VALID_EMAIL);
        String nonce     = UUID.randomUUID().toString();
        long   timestamp = Instant.now().getEpochSecond();
        String message   = VALID_EMAIL + ":" + nonce + ":" + timestamp;
        String hmac      = hmacService.compute(user.getPassword(), message);

        SsoToken token = authService.login(VALID_EMAIL, nonce, timestamp, hmac);
        assertNotNull(token.getAccessToken());
    }

    // Test 14 : Non divulgation des erreurs
    @Test
    void testNonDivulgationErreurs() {
        registerUser();
        String nonce     = UUID.randomUUID().toString();
        long   timestamp = Instant.now().getEpochSecond();

        // Email inconnu
        Exception e1 = assertThrows(AuthenticationFailedException.class, () ->
                authService.login("inconnu@test.com", nonce, timestamp, "hmac"));

        // Mauvais HMAC
        Exception e2 = assertThrows(AuthenticationFailedException.class, () ->
                authService.login(VALID_EMAIL, nonce, timestamp, "mauvais"));

        // Même message d'erreur
        assertEquals(e1.getMessage(), e2.getMessage());
    }

    // Test 15 : Accès /api/me sans token
    @Test
    void testAccesMeSansToken() {
        assertThrows(AuthenticationFailedException.class, () ->
                authService.validateToken(null));
    }
}