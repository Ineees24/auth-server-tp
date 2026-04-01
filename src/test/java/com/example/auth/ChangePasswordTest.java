package com.example.auth;

import com.example.auth.exception.*;
import com.example.auth.service.AuthService;
import com.example.auth.service.MasterKeyService;
import com.example.auth.service.HmacService;
import com.example.auth.entity.SsoToken;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class ChangePasswordTest {

    @Autowired private MockMvc          mockMvc;
    @Autowired private AuthService      authService;
    @Autowired private HmacService      hmacService;
    @Autowired private MasterKeyService masterKeyService;

    private static final String EMAIL        = "change@test.com";
    private static final String OLD_PASSWORD = "Abcdef123!@#";
    private static final String NEW_PASSWORD = "NewPassword123!@";

    private void registerUser() {
        authService.register(EMAIL, OLD_PASSWORD);
    }

    /** Helper : login et retourne le token */
    private String getToken() throws Exception {
        registerUser();
        var user     = authService.findByEmail(EMAIL);
        String plain = masterKeyService.decrypt(user.getPassword());
        String nonce = UUID.randomUUID().toString();
        long ts      = Instant.now().getEpochSecond();
        String msg   = EMAIL + ":" + nonce + ":" + ts;
        String hmac  = hmacService.compute(plain, msg);
        SsoToken token = authService.login(EMAIL, nonce, ts, hmac);
        return token.getAccessToken();
    }

    // Test 1 : Changement de mot de passe réussi
    @Test
    void testChangePasswordOK() throws Exception {
        String token = getToken();

        mockMvc.perform(put("/api/auth/change-password")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                    {
                        "email": "%s",
                        "oldPassword": "%s",
                        "newPassword": "%s",
                        "confirmPassword": "%s"
                    }
                    """.formatted(EMAIL, OLD_PASSWORD, NEW_PASSWORD, NEW_PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Mot de passe change avec succes"));
    }

    // Test 2 : Ancien mot de passe incorrect
    @Test
    void testChangePasswordAncienMotDePasseIncorrect() throws Exception {
        String token = getToken();

        mockMvc.perform(put("/api/auth/change-password")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                    {
                        "email": "%s",
                        "oldPassword": "MauvaisMotDePasse1!",
                        "newPassword": "%s",
                        "confirmPassword": "%s"
                    }
                    """.formatted(EMAIL, NEW_PASSWORD, NEW_PASSWORD)))
                .andExpect(status().isUnauthorized());
    }

    // Test 3 : Confirmation différente
    @Test
    void testChangePasswordConfirmationDifferente() throws Exception {
        String token = getToken();

        mockMvc.perform(put("/api/auth/change-password")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                    {
                        "email": "%s",
                        "oldPassword": "%s",
                        "newPassword": "%s",
                        "confirmPassword": "AutreMotDePasse1!"
                    }
                    """.formatted(EMAIL, OLD_PASSWORD, NEW_PASSWORD)))
                .andExpect(status().isBadRequest());
    }

    // Test 4 : Nouveau mot de passe trop faible
    @Test
    void testChangePasswordMotDePasseTropFaible() throws Exception {
        String token = getToken();

        mockMvc.perform(put("/api/auth/change-password")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                    {
                        "email": "%s",
                        "oldPassword": "%s",
                        "newPassword": "faible",
                        "confirmPassword": "faible"
                    }
                    """.formatted(EMAIL, OLD_PASSWORD)))
                .andExpect(status().isBadRequest());
    }

    // Test 5 : Utilisateur inexistant
    @Test
    void testChangePasswordUtilisateurInexistant() throws Exception {
        registerUser();
        var user     = authService.findByEmail(EMAIL);
        String plain = masterKeyService.decrypt(user.getPassword());
        String nonce = UUID.randomUUID().toString();
        long ts      = Instant.now().getEpochSecond();
        String hmac  = hmacService.compute(plain, EMAIL + ":" + nonce + ":" + ts);
        SsoToken token = authService.login(EMAIL, nonce, ts, hmac);

        mockMvc.perform(put("/api/auth/change-password")
                        .header("Authorization", "Bearer " + token.getAccessToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                    {
                        "email": "inconnu@test.com",
                        "oldPassword": "%s",
                        "newPassword": "%s",
                        "confirmPassword": "%s"
                    }
                    """.formatted(OLD_PASSWORD, NEW_PASSWORD, NEW_PASSWORD)))
                .andExpect(status().isUnauthorized());
    }

    // Test 6 : Sans token → 401
    @Test
    void testChangePasswordSansToken() throws Exception {
        mockMvc.perform(put("/api/auth/change-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                    {
                        "email": "%s",
                        "oldPassword": "%s",
                        "newPassword": "%s",
                        "confirmPassword": "%s"
                    }
                    """.formatted(EMAIL, OLD_PASSWORD, NEW_PASSWORD, NEW_PASSWORD)))
                .andExpect(status().isUnauthorized());
    }

    // Test 7 : Vérification via service direct - changement OK
    @Test
    void testChangePasswordServiceOK() {
        registerUser();
        assertDoesNotThrow(() ->
                authService.changePassword(EMAIL, OLD_PASSWORD, NEW_PASSWORD, NEW_PASSWORD));
    }

    // Test 8 : Vérification que le nouveau mot de passe fonctionne après changement
    @Test
    void testNouveauMotDePasseFonctionneApresChangement() throws Exception {
        String token = getToken();

        // Changer le mot de passe
        mockMvc.perform(put("/api/auth/change-password")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                    {
                        "email": "%s",
                        "oldPassword": "%s",
                        "newPassword": "%s",
                        "confirmPassword": "%s"
                    }
                    """.formatted(EMAIL, OLD_PASSWORD, NEW_PASSWORD, NEW_PASSWORD)))
                .andExpect(status().isOk());

        // Se connecter avec le nouveau mot de passe
        var user     = authService.findByEmail(EMAIL);
        String plain = masterKeyService.decrypt(user.getPassword());
        String nonce = UUID.randomUUID().toString();
        long ts      = Instant.now().getEpochSecond();
        String hmac  = hmacService.compute(plain, EMAIL + ":" + nonce + ":" + ts);

        SsoToken newToken = authService.login(EMAIL, nonce, ts, hmac);
        assertNotNull(newToken.getAccessToken());
    }
}