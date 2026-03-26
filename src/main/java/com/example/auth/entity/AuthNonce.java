package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entité représentant un nonce utilisé pour l'anti-rejeu.
 * TP3 : chaque nonce ne peut être utilisé qu'une seule fois.
 *
 * AVERTISSEMENT : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
@Entity
@Table(name = "auth_nonce",
        uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "nonce"}))
public class AuthNonce {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private String nonce;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false)
    private boolean consumed = false;

    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();

    public AuthNonce() {}

    public AuthNonce(User user, String nonce, LocalDateTime expiresAt) {
        this.user      = user;
        this.nonce     = nonce;
        this.expiresAt = expiresAt;
    }

    // Getters & Setters
    public Long getId()                        { return id; }
    public User getUser()                      { return user; }
    public String getNonce()                   { return nonce; }
    public LocalDateTime getExpiresAt()        { return expiresAt; }
    public boolean isConsumed()                { return consumed; }
    public void setConsumed(boolean consumed)  { this.consumed = consumed; }
    public LocalDateTime getCreatedAt()        { return createdAt; }
}