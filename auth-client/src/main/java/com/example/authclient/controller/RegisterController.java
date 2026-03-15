package com.example.authclient.controller;

import com.example.authclient.App;
import com.example.authclient.service.AuthService;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;

/**
 * Controller de la vue d'inscription (register.fxml).
 * Gère le formulaire POST /api/auth/register.
 */
public class RegisterController {

    @FXML private TextField emailField;
    @FXML private PasswordField passwordField;
    @FXML private Button registerButton;
    @FXML private Label messageLabel;
    @FXML private Label strengthLabel;
    @FXML private ProgressIndicator loadingIndicator;

    @FXML
    public void initialize() {
        loadingIndicator.setVisible(false);
        messageLabel.setText("");
        strengthLabel.setText("");

        // Indicateur de force du mot de passe en temps réel
        passwordField.textProperty().addListener((obs, oldVal, newVal) -> {
            updatePasswordStrength(newVal);
        });
    }

    /** Appelé quand on clique sur "Créer le compte" */
    @FXML
    public void onRegisterClicked() {
        String email    = emailField.getText().trim();
        String password = passwordField.getText();

        // Validations côté client
        if (email.isEmpty() || password.isEmpty()) {
            showMessage("Veuillez remplir tous les champs.", "error");
            return;
        }
        if (!email.contains("@")) {
            showMessage("Format d'email invalide.", "error");
            return;
        }
        if (password.length() < 4) {
            showMessage("Mot de passe trop court (minimum 4 caractères).", "error");
            return;
        }

        setLoading(true);

        new Thread(() -> {
            AuthService.ApiResponse response = AuthService.register(email, password);

            Platform.runLater(() -> {
                setLoading(false);
                if (response.isSuccess()) {
                    showMessage("Compte créé avec succès ! Redirection...", "success");
                    // Attendre 1 seconde puis aller sur la page de login
                    new Thread(() -> {
                        try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
                        Platform.runLater(() -> {
                            try {
                                App.navigateTo("login.fxml", "Connexion");
                            } catch (Exception e) {
                                showMessage("Erreur navigation : " + e.getMessage(), "error");
                            }
                        });
                    }).start();
                } else if (response.status == 409) {
                    showMessage("Cet email est déjà utilisé.", "error");
                } else if (response.status == 400) {
                    showMessage("Données invalides : " + extractMessage(response.body), "error");
                } else if (response.status == 0) {
                    showMessage("Serveur inaccessible. Vérifiez que Spring Boot tourne.", "error");
                } else {
                    showMessage("Erreur " + response.status, "error");
                }
            });
        }).start();
    }

    /** Retour vers la page de connexion */
    @FXML
    public void onGoToLogin() {
        try {
            App.navigateTo("login.fxml", "Connexion");
        } catch (Exception e) {
            showMessage("Erreur : " + e.getMessage(), "error");
        }
    }

    /** Met à jour l'indicateur de force du mot de passe */
    private void updatePasswordStrength(String password) {
        strengthLabel.getStyleClass().removeAll(
                "strength-weak", "strength-medium", "strength-strong");

        if (password.isEmpty()) {
            strengthLabel.setText("");
            return;
        }

        boolean hasMin    = password.length() >= 12;
        boolean hasUpper  = password.matches(".*[A-Z].*");
        boolean hasLower  = password.matches(".*[a-z].*");
        boolean hasDigit  = password.matches(".*[0-9].*");
        boolean hasSpec   = password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*");

        int score = 0;
        if (hasMin)   score++;
        if (hasUpper) score++;
        if (hasLower) score++;
        if (hasDigit) score++;
        if (hasSpec)  score++;

        if (score <= 2) {
            strengthLabel.setText("🔴 Non conforme");
            strengthLabel.getStyleClass().add("strength-weak");
        } else if (score <= 4) {
            strengthLabel.setText("🟠 Conforme mais faible");
            strengthLabel.getStyleClass().add("strength-medium");
        } else {
            strengthLabel.setText("🟢 Conforme et bon niveau");
            strengthLabel.getStyleClass().add("strength-strong");
        }
    }

    private void setLoading(boolean loading) {
        loadingIndicator.setVisible(loading);
        registerButton.setDisable(loading);
    }

    private void showMessage(String text, String type) {
        messageLabel.setText(text);
        messageLabel.getStyleClass().removeAll("msg-error", "msg-success", "msg-warn");
        messageLabel.getStyleClass().add("msg-" + type);
    }

    private String extractMessage(String json) {
        String msg = AuthService.extractJson(json, "message");
        return msg != null ? msg : json;
    }
}