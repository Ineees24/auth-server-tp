package com.example.authclient.controller;

import com.example.authclient.App;
import com.example.authclient.service.AuthService;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;

/**
 * Controller de la vue de connexion (login.fxml).
 * Gère le formulaire POST /api/auth/login.
 */
public class LoginController {

    @FXML private TextField emailField;
    @FXML private PasswordField passwordField;
    @FXML private Button loginButton;
    @FXML private Label messageLabel;
    @FXML private ProgressIndicator loadingIndicator;

    @FXML
    public void initialize() {
        loadingIndicator.setVisible(false);
        messageLabel.setText("");

        // Pré-remplir avec le compte de test
        emailField.setText("toto@example.com");
        passwordField.setText("pwd1234");
    }

    /** Appelé quand on clique sur "Se connecter" */
    @FXML
    public void onLoginClicked() {
        String email    = emailField.getText().trim();
        String password = passwordField.getText();

        // Validation côté client
        if (email.isEmpty() || password.isEmpty()) {
            showMessage("Veuillez remplir tous les champs.", "error");
            return;
        }
        if (!email.contains("@")) {
            showMessage("Format d'email invalide.", "error");
            return;
        }

        setLoading(true);

        // Appel HTTP dans un thread séparé pour ne pas bloquer l'UI
        new Thread(() -> {
            AuthService.ApiResponse response = AuthService.login(email, password);

            Platform.runLater(() -> {
                setLoading(false);
                if (response.isSuccess()) {
                    showMessage("Connexion réussie !", "success");
                    try {
                        App.navigateTo("profile.fxml", "Mon Profil");
                    } catch (Exception e) {
                        showMessage("Erreur de navigation : " + e.getMessage(), "error");
                    }
                } else if (response.status == 401) {
                    showMessage("Email ou mot de passe incorrect.", "error");
                } else if (response.status == 429) {
                    showMessage("Compte bloqué ! Trop de tentatives. Réessayez dans 2 minutes.", "error");
                } else if (response.status == 0) {
                    showMessage("Serveur inaccessible. Vérifiez que Spring Boot tourne.", "error");
                } else {
                    showMessage("Erreur " + response.status + " : " + response.body, "error");
                }
            });
        }).start();
    }

    /** Navigue vers la page d'inscription */
    @FXML
    public void onGoToRegister() {
        try {
            App.navigateTo("register.fxml", "Inscription");
        } catch (Exception e) {
            showMessage("Erreur : " + e.getMessage(), "error");
        }
    }

    private void setLoading(boolean loading) {
        loadingIndicator.setVisible(loading);
        loginButton.setDisable(loading);
    }

    private void showMessage(String text, String type) {
        messageLabel.setText(text);
        messageLabel.getStyleClass().removeAll("msg-error", "msg-success", "msg-warn");
        messageLabel.getStyleClass().add("msg-" + type);
    }
}