package com.example.auth.entity;

/**
 * DTO représentant la requête de changement de mot de passe.
 * TP5 : l'utilisateur doit être authentifié et fournir l'ancien mot de passe.
 *
 * AVERTISSEMENT : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
public class ChangePasswordRequest {

    private String email;
    private String oldPassword;
    private String newPassword;
    private String confirmPassword;

    public ChangePasswordRequest() {}

    public String getEmail()           { return email; }
    public String getOldPassword()     { return oldPassword; }
    public String getNewPassword()     { return newPassword; }
    public String getConfirmPassword() { return confirmPassword; }

    public void setEmail(String email)                     { this.email = email; }
    public void setOldPassword(String oldPassword)         { this.oldPassword = oldPassword; }
    public void setNewPassword(String newPassword)         { this.newPassword = newPassword; }
    public void setConfirmPassword(String confirmPassword) { this.confirmPassword = confirmPassword; }
}