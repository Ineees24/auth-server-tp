package com.example.auth;

import com.example.auth.exception.*;
import com.example.auth.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class AuthServiceTest {

    @Autowired
    private AuthService authService;

    // Test 1: Inscription réussie
    @Test
    void testRegisterOK() {
        assertDoesNotThrow(() -> authService.register("new@test.com", "abcd"));
    }

    // Test 2: Email vide
    @Test
    void testRegisterEmailVide() {
        assertThrows(InvalidInputException.class, () -> authService.register("", "abcd"));
    }

    // Test 3: Email format incorrect
    @Test
    void testRegisterEmailFormatIncorrect() {
        assertThrows(InvalidInputException.class, () -> authService.register("pasunmail", "abcd"));
    }

    // Test 4: Mot de passe trop court
    @Test
    void testRegisterPasswordTropCourt() {
        assertThrows(InvalidInputException.class, () -> authService.register("a@b.com", "abc"));
    }

    // Test 5: Email déjà existant
    @Test
    void testRegisterEmailDejaExistant() {
        authService.register("dup@test.com", "abcd");
        assertThrows(ResourceConflictException.class, () -> authService.register("dup@test.com", "abcd"));
    }

    // Test 6: Login réussi
    @Test
    void testLoginOK() {
        authService.register("login@test.com", "abcd");
        assertTrue(authService.login("login@test.com", "abcd"));
    }

    // Test 7: Login échoue si mauvais mot de passe
    @Test
    void testLoginMauvaisPassword() {
        authService.register("bad@test.com", "abcd");

        assertFalse(authService.login("bad@test.com", "wrong"));
    }

    // Test 8: Login échoue si email inconnu
    @Test
    void testLoginEmailInconnu() {
        assertFalse(authService.login("inconnu@test.com", "abcd"));
    }
}
