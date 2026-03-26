package com.example.auth.service;

import org.springframework.stereotype.Service;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * Service de calcul et vérification HMAC-SHA256.
 * TP3 : permet de vérifier la preuve d'identité sans recevoir le mot de passe.
 *
 * AVERTISSEMENT : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
@Service
public class HmacService {

    /**
     * Calcule HMAC-SHA256(key=password, data=message).
     * @param key  le mot de passe en clair
     * @param data le message à signer (email:nonce:timestamp)
     * @return le HMAC en hexadécimal
     */
    public String compute(String key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(
                key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(keySpec);
        byte[] rawHmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(rawHmac);
    }

    /**
     * Compare deux HMAC en temps constant pour éviter les timing attacks.
     * @param a premier HMAC
     * @param b deuxième HMAC
     * @return true si égaux
     */
    public boolean compareConstantTime(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8)
        );
    }
}