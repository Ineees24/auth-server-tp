package com.example.auth.service;

import com.example.auth.repository.AuthNonceRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Service de nettoyage automatique des nonces expirés.
 * TP3 : supprime les nonces expirés toutes les 5 minutes.
 *
 * AVERTISSEMENT : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
@Service
public class NonceCleanupService {

    private static final Logger logger =
            LoggerFactory.getLogger(NonceCleanupService.class);

    private final AuthNonceRepository nonceRepository;

    public NonceCleanupService(AuthNonceRepository nonceRepository) {
        this.nonceRepository = nonceRepository;
    }

    /**
     * Supprime automatiquement les nonces expirés toutes les 5 minutes.
     */
    @Scheduled(fixedRate = 300000)
    public void cleanExpiredNonces() {
        List<com.example.auth.entity.AuthNonce> all =
                nonceRepository.findAll();

        long deleted = all.stream()
                .filter(n -> n.getExpiresAt().isBefore(LocalDateTime.now()))
                .peek(n -> nonceRepository.delete(n))
                .count();

        if (deleted > 0) {
            logger.info("Nonces expires supprimes : {}", deleted);
        }
    }
}