package com.example.auth.repository;

import com.example.auth.entity.AuthNonce;
import com.example.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository pour la gestion des nonces anti-rejeu.
 * TP3 : chaque nonce est unique par utilisateur.
 */
public interface AuthNonceRepository extends JpaRepository<AuthNonce, Long> {

    Optional<AuthNonce> findByUserAndNonce(User user, String nonce);

    List<AuthNonce> findByExpiresAtBefore(LocalDateTime dateTime);
}