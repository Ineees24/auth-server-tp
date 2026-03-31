package com.example.auth;

import com.example.auth.exception.*;
import com.example.auth.entity.SsoToken;
import com.example.auth.service.AuthService;
import com.example.auth.service.HmacService;
import com.example.auth.service.MasterKeyService;
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

    @Autowired private AuthService     authService;
    @Autowired private HmacService     hmacService;
    @Autowired private MasterKeyService masterKeyService;

    private static final String VALID_EMAIL    = "test@example.com";
    private static final String VALID_PASSWORD = "Abcdef123!@#";

    // ── Helper ────────────────────────────────────────────────────────────────

    private void registerUser() {
        authService.register(VALID_EMAIL, VALID_PASSWORD);
    }

    /** Déchiffre le mot de passe stocké puis calcule le HMAC */
    private SsoToken loginWithRealHmac(String email) throws Exception {
        var user      = authService.findByEmail(email);
        String plain  = masterKeyService.decrypt(user.getPassword());
        String nonce  = UUID.randomUUID().toString();
        long   ts     = Instant.now().getEpochSecond();
        String msg    = email + ":" + nonce + ":" + ts;
        String hmac   = hmacService.compute(plain, msg);
        return authService.login(email, nonce, ts, hmac);
    }

    // ── Tests inscription ─────────────────────────────────────────────────────

    @Test
    void testRegisterOK() {
        assertDoesNotThrow(() ->
                authService.register(VALID_EMAIL, VALID_PASSWORD));
    }

    @Test
    void testRegisterEmailVide() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("", VALID_PASSWORD));
    }

    @Test
    void testRegisterEmailFormatIncorrect() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("pasunmail", VALID_PASSWORD));
    }

    @Test
    void testRegisterPasswordTropCourt() {
        assertThrows(InvalidInputException.class, () ->
                authService.register(VALID_EMAIL, "abc"));
    }

    @Test
    void testRegisterEmailDejaExistant() {
        authService.register(VALID_EMAIL, VALID_PASSWORD);
        assertThrows(ResourceConflictException.class, () ->
                authService.register(VALID_EMAIL, VALID_PASSWORD));
    }

    // ── Tests login HMAC ──────────────────────────────────────────────────────

    @Test
    void testLoginOKHmacValide() throws Exception {
        registerUser();
        SsoToken token = loginWithRealHmac(VALID_EMAIL);
        assertNotNull(token);
        assertNotNull(token.getAccessToken());
        assertNotNull(token.getExpiresAt());
    }

    @Test
    void testLoginKOHmacInvalide() {
        registerUser();
        String nonce  = UUID.randomUUID().toString();
        long timestamp = Instant.now().getEpochSecond();
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login(VALID_EMAIL, nonce, timestamp, "mauvais_hmac"));
    }

    @Test
    void testLoginKOTimestampExpire() throws Exception {
        registerUser();
        var user     = authService.findByEmail(VALID_EMAIL);
        String plain = masterKeyService.decrypt(user.getPassword());
        String nonce = UUID.randomUUID().toString();
        long ts      = Instant.now().getEpochSecond() - 120;
        String hmac  = hmacService.compute(plain, VALID_EMAIL + ":" + nonce + ":" + ts);
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login(VALID_EMAIL, nonce, ts, hmac));
    }

    @Test
    void testLoginKOTimestampFutur() throws Exception {
        registerUser();
        var user     = authService.findByEmail(VALID_EMAIL);
        String plain = masterKeyService.decrypt(user.getPassword());
        String nonce = UUID.randomUUID().toString();
        long ts      = Instant.now().getEpochSecond() + 120;
        String hmac  = hmacService.compute(plain, VALID_EMAIL + ":" + nonce + ":" + ts);
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login(VALID_EMAIL, nonce, ts, hmac));
    }

    @Test
    void testLoginKONonceDejaUtilise() throws Exception {
        registerUser();
        var user     = authService.findByEmail(VALID_EMAIL);
        String plain = masterKeyService.decrypt(user.getPassword());
        String nonce = UUID.randomUUID().toString();
        long ts      = Instant.now().getEpochSecond();
        String hmac  = hmacService.compute(plain, VALID_EMAIL + ":" + nonce + ":" + ts);

        authService.login(VALID_EMAIL, nonce, ts, hmac);

        assertThrows(AuthenticationFailedException.class, () ->
                authService.login(VALID_EMAIL, nonce, ts, hmac));
    }

    @Test
    void testLoginKOEmailInconnu() {
        String nonce = UUID.randomUUID().toString();
        long ts      = Instant.now().getEpochSecond();
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login("inconnu@test.com", nonce, ts, "hmac"));
    }

    @Test
    void testComparaisonTempsConstant() {
        assertTrue(hmacService.compareConstantTime("abc123", "abc123"));
        assertFalse(hmacService.compareConstantTime("abc123", "different"));
    }

    @Test
    void testTokenEmisEtAccesMe() throws Exception {
        registerUser();
        SsoToken token = loginWithRealHmac(VALID_EMAIL);
        assertNotNull(token.getAccessToken());
    }

    @Test
    void testNonDivulgationErreurs() {
        registerUser();
        String nonce = UUID.randomUUID().toString();
        long ts      = Instant.now().getEpochSecond();

        Exception e1 = assertThrows(AuthenticationFailedException.class, () ->
                authService.login("inconnu@test.com", nonce, ts, "hmac"));
        Exception e2 = assertThrows(AuthenticationFailedException.class, () ->
                authService.login(VALID_EMAIL, nonce, ts, "mauvais"));

        assertEquals(e1.getMessage(), e2.getMessage());
    }

    @Test
    void testAccesMeSansToken() {
        assertThrows(AuthenticationFailedException.class, () ->
                authService.validateToken(null));
    }

    @Test
    void testHmacDifferentPourMessagesDifferents() throws Exception {
        String key  = "motdepasse";
        String hmac1 = hmacService.compute(key, "user@test.com:nonce1:123456");
        String hmac2 = hmacService.compute(key, "user@test.com:nonce2:123456");
        assertNotEquals(hmac1, hmac2);
    }

    @Test
    void testPasswordSansMajuscule() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("a@b.com", "abcdef123!@#"));
    }

    @Test
    void testPasswordSansChiffre() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("a@b.com", "Abcdefghij!@"));
    }

    @Test
    void testPasswordSansSpecial() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("a@b.com", "Abcdefgh1234"));
    }

    @Test
    void testTokenInvalide() {
        assertThrows(AuthenticationFailedException.class, () ->
                authService.validateToken("token_inexistant"));
    }

    @Test
    void testValidateTokenOK() throws Exception {
        registerUser();
        SsoToken token = loginWithRealHmac(VALID_EMAIL);
        String email   = authService.validateToken(token.getAccessToken());
        assertEquals(VALID_EMAIL, email);
    }

    @Test
    void testRegisterEmailNull() {
        assertThrows(InvalidInputException.class, () ->
                authService.register(null, VALID_PASSWORD));
    }

    @Test
    void testRegisterConflitEmail() {
        authService.register(VALID_EMAIL, VALID_PASSWORD);
        assertThrows(ResourceConflictException.class, () ->
                authService.register(VALID_EMAIL, VALID_PASSWORD));
    }

    @Test
    void testPasswordSansMinuscule() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("a@b.com", "ABCDEF123!@#"));
    }

    @Test
    void testPasswordExactement12Caracteres() {
        assertDoesNotThrow(() ->
                authService.register("new2@test.com", "Abcdefg123!@"));
    }

    @Test
    void testFindByEmailInconnu() {
        assertThrows(AuthenticationFailedException.class, () ->
                authService.findByEmail("inconnu@test.com"));
    }

    @Test
    void testHmacDeterministe() throws Exception {
        String h1 = hmacService.compute("cle", "email:nonce:123");
        String h2 = hmacService.compute("cle", "email:nonce:123");
        assertEquals(h1, h2);
    }
}