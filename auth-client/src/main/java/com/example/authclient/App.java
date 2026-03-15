package com.example.authclient;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

/**
 * Point d'entrée principal de l'application cliente.
 * Lance la vue de connexion au démarrage.
 */
public class App extends Application {

    private static Stage primaryStage;

    @Override
    public void start(Stage stage) throws IOException {
        primaryStage = stage;
        stage.setTitle("Auth Server — TP1");
        stage.setResizable(false);
        navigateTo("login.fxml", "🔐 Connexion");
        stage.show();
    }

    /**
     * Méthode statique pour naviguer entre les vues depuis n'importe quel controller.
     * @param fxmlFile  nom du fichier FXML (ex: "login.fxml")
     * @param title     titre de la fenêtre
     */
    public static void navigateTo(String fxmlFile, String title) throws IOException {
        FXMLLoader loader = new FXMLLoader(
                App.class.getResource("/com/example/authclient/" + fxmlFile)
        );
        Scene scene = new Scene(loader.load());
        primaryStage.setTitle("Auth Server TP1 — " + title);
        primaryStage.setScene(scene);
    }

    public static Stage getPrimaryStage() {
        return primaryStage;
    }

    public static void main(String[] args) {
        launch();
    }
}