package com.example.authclient.controller;

import com.example.authclient.App;
import com.example.authclient.service.AuthService;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;

/**
 * Controller de la vue profil (profile.fxml).
 * Gère l'appel GET /api/auth/me avec le token Bearer.
 */
public class ProfileController {

    @FXML private Label welcomeLabel;
    @FXML private Label emailLabel;
    @FXML private Label tokenLabel;
    @FXML private Label messageLabel;
    @FXML private Button refreshButton;
    @FXML private ProgressIndicator loadingIndicator;

    @FXML
    public void initialize() {
        loadingIndicator.setVisible(false);
        messageLabel.setText("");

        // Afficher l'email stocké en session
        if (AuthService.isLoggedIn()) {
            welcomeLabel.setText("Bienvenue, " + AuthService.getEmail() + " !");
            emailLabel.setText(AuthService.getEmail());
            String token = AuthService.getToken();
            // Afficher seulement les 20 premiers caractères du token
            tokenLabel.setText(token.substring(0, Math.min(token.length(), 20)) + "...");
        }

        // Charger automatiquement les données au démarrage
        onRefreshClicked();
    }

    /** Appelle GET /api/auth/me pour vérifier le token */
    @FXML
    public void onRefreshClicked() {
        if (!AuthService.isLoggedIn()) {
            showMessage("Vous n'êtes pas connecté.", "error");
            return;
        }

        loadingIndicator.setVisible(true);
        refreshButton.setDisable(true);

        new Thread(() -> {
            AuthService.ApiResponse response = AuthService.getMe();

            Platform.runLater(() -> {
                loadingIndicator.setVisible(false);
                refreshButton.setDisable(false);

                if (response.isSuccess()) {
                    String serverEmail = AuthService.extractJson(response.body, "email");
                    if (serverEmail != null) {
                        emailLabel.setText(serverEmail);
                        welcomeLabel.setText("Bienvenue, " + serverEmail + " !");
                    }
                    showMessage("✅ Profil chargé avec succès.", "success");
                } else if (response.status == 401) {
                    showMessage("Token invalide ou expiré. Reconnectez-vous.", "error");
                    AuthService.logout();
                } else if (response.status == 0) {
                    showMessage("Serveur inaccessible.", "error");
                } else {
                    showMessage("Erreur " + response.status, "error");
                }
            });
        }).start();
    }

    /** Déconnexion : supprime le token et retourne au login */
    @FXML
    public void onLogoutClicked() {
        AuthService.logout();
        try {
            App.navigateTo("login.fxml", "Connexion");
        } catch (Exception e) {
            showMessage("Erreur : " + e.getMessage(), "error");
        }
    }

    private void showMessage(String text, String type) {
        messageLabel.setText(text);
        messageLabel.getStyleClass().removeAll("msg-error", "msg-success", "msg-warn");
        messageLabel.getStyleClass().add("msg-" + type);
    }
}