module com.example.authclient {
    requires javafx.controls;
    requires javafx.fxml;
    requires java.net.http;

    opens com.example.authclient to javafx.fxml;
    opens com.example.authclient.controller to javafx.fxml;

    exports com.example.authclient;
    exports com.example.authclient.controller;
    exports com.example.authclient.service;
}