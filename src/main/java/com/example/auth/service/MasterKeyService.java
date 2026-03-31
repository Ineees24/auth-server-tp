package com.example.auth.service;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Service de chiffrement/déchiffrement des mots de passe via AES-GCM.
 * TP4 : la Master Key est injectée via variable d'environnement APP_MASTER_KEY.
 * Si la clé est absente, l'application refuse de démarrer.
 *
 * AVERTISSEMENT : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
@Service
public class MasterKeyService {

    private static final String ALGORITHM   = "AES/GCM/NoPadding";
    private static final int    GCM_IV_LEN  = 12;  // 96 bits
    private static final int    GCM_TAG_LEN = 128; // 128 bits

    @Value("${app.master.key:#{null}}")
    private String springKey;

    private SecretKey secretKey;

    /**
     * Vérifie et charge la Master Key au démarrage.
     * Ordre de priorité :
     * 1. Variable d'environnement APP_MASTER_KEY
     * 2. Propriété système -DAPP_MASTER_KEY
     * 3. Propriété Spring app.master.key (pour les tests)
     * L'application refuse de démarrer si aucune clé n'est trouvée.
     */
    @PostConstruct
    public void init() {
        String rawKey = System.getenv("APP_MASTER_KEY");

        if (rawKey == null || rawKey.isBlank()) {
            rawKey = System.getProperty("APP_MASTER_KEY");
        }

        if (rawKey == null || rawKey.isBlank()) {
            rawKey = springKey;
        }

        if (rawKey == null || rawKey.isBlank()) {
            throw new IllegalStateException(
                    "APP_MASTER_KEY est absente. L'application ne peut pas démarrer.");
        }

        byte[] keyBytes = deriveKey(rawKey);
        this.secretKey  = new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Chiffre un mot de passe en clair.
     * Format de stockage : v1:Base64(iv):Base64(ciphertext)
     * @param plaintext le mot de passe en clair
     * @return la chaîne chiffrée
     */
    public String encrypt(String plaintext) throws Exception {
        byte[] iv = new byte[GCM_IV_LEN];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LEN, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));

        return "v1:" +
                Base64.getEncoder().encodeToString(iv) + ":" +
                Base64.getEncoder().encodeToString(ciphertext);
    }

    /**
     * Déchiffre un mot de passe chiffré.
     * @param encrypted la chaîne au format v1:Base64(iv):Base64(ciphertext)
     * @return le mot de passe en clair
     */
    public String decrypt(String encrypted) throws Exception {
        String[] parts = encrypted.split(":");
        if (parts.length != 3 || !parts[0].equals("v1")) {
            throw new IllegalArgumentException("Format de chiffrement invalide");
        }

        byte[] iv         = Base64.getDecoder().decode(parts[1]);
        byte[] ciphertext = Base64.getDecoder().decode(parts[2]);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LEN, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, "UTF-8");
    }

    /**
     * Dérive une clé AES 256 bits depuis une chaîne.
     */
    private byte[] deriveKey(String rawKey) {
        byte[] raw    = rawKey.getBytes();
        byte[] result = new byte[32];
        System.arraycopy(raw, 0, result, 0,
                Math.min(raw.length, result.length));
        return result;
    }
}