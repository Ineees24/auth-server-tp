package com.example.auth;

import com.example.auth.service.AuthService;
import com.example.auth.service.HmacService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class AuthControllerTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private AuthService authService;
    @Autowired private HmacService hmacService;

    private static final String EMAIL    = "ctrl@test.com";
    private static final String PASSWORD = "Abcdef123!@#";

    // Test 1 : POST /register OK → 200
    @Test
    void testRegisterOK() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .param("email", EMAIL)
                        .param("password", PASSWORD))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Inscription reussie"));
    }

    // Test 2 : POST /register email invalide → 400
    @Test
    void testRegisterEmailInvalide() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .param("email", "pasunemail")
                        .param("password", PASSWORD))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    // Test 3 : POST /register email déjà existant → 409
    @Test
    void testRegisterEmailDejaExistant() throws Exception {
        authService.register(EMAIL, PASSWORD);

        mockMvc.perform(post("/api/auth/register")
                        .param("email", EMAIL)
                        .param("password", PASSWORD))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409));
    }

    // Test 4 : POST /register mot de passe trop court → 400
    @Test
    void testRegisterPasswordTropCourt() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .param("email", EMAIL)
                        .param("password", "abc"))
                .andExpect(status().isBadRequest());
    }

    // Test 5 : POST /login OK → 200 avec accessToken
    @Test
    void testLoginOK() throws Exception {
        authService.register(EMAIL, PASSWORD);
        var user      = authService.findByEmail(EMAIL);
        String nonce  = UUID.randomUUID().toString();
        long ts       = Instant.now().getEpochSecond();
        String msg    = EMAIL + ":" + nonce + ":" + ts;
        String hmac   = hmacService.compute(user.getPassword(), msg);

        mockMvc.perform(post("/api/auth/login")
                        .param("email",     EMAIL)
                        .param("nonce",     nonce)
                        .param("timestamp", String.valueOf(ts))
                        .param("hmac",      hmac))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.expiresAt").exists());
    }

    // Test 6 : POST /login HMAC invalide → 401
    @Test
    void testLoginHmacInvalide() throws Exception {
        authService.register(EMAIL, PASSWORD);
        String nonce = UUID.randomUUID().toString();
        long ts      = Instant.now().getEpochSecond();

        mockMvc.perform(post("/api/auth/login")
                        .param("email",     EMAIL)
                        .param("nonce",     nonce)
                        .param("timestamp", String.valueOf(ts))
                        .param("hmac",      "mauvais_hmac"))
                .andExpect(status().isUnauthorized());
    }

    // Test 7 : GET /me sans token → 401
    @Test
    void testMeSansToken() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    // Test 8 : GET /me avec token valide → 200
    @Test
    void testMeAvecTokenValide() throws Exception {
        authService.register(EMAIL, PASSWORD);
        var user     = authService.findByEmail(EMAIL);
        String nonce = UUID.randomUUID().toString();
        long ts      = Instant.now().getEpochSecond();
        String msg   = EMAIL + ":" + nonce + ":" + ts;
        String hmac  = hmacService.compute(user.getPassword(), msg);

        var result = mockMvc.perform(post("/api/auth/login")
                        .param("email",     EMAIL)
                        .param("nonce",     nonce)
                        .param("timestamp", String.valueOf(ts))
                        .param("hmac",      hmac))
                .andReturn();

        String body  = result.getResponse().getContentAsString();
        String token = body.split("\"accessToken\":\"")[1].split("\"")[0];

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(EMAIL));
    }

    // Test 9 : GET /me avec token invalide → 401
    @Test
    void testMeAvecTokenInvalide() throws Exception {
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer token_invalide"))
                .andExpect(status().isUnauthorized());
    }

    // Test 10 : POST /login timestamp expiré → 401
    @Test
    void testLoginTimestampExpire() throws Exception {
        authService.register(EMAIL, PASSWORD);
        var user     = authService.findByEmail(EMAIL);
        String nonce = UUID.randomUUID().toString();
        long ts      = Instant.now().getEpochSecond() - 120;
        String msg   = EMAIL + ":" + nonce + ":" + ts;
        String hmac  = hmacService.compute(user.getPassword(), msg);

        mockMvc.perform(post("/api/auth/login")
                        .param("email",     EMAIL)
                        .param("nonce",     nonce)
                        .param("timestamp", String.valueOf(ts))
                        .param("hmac",      hmac))
                .andExpect(status().isUnauthorized());
    }
}