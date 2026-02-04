package com.Authentication.AuthService.services.auth.crypto;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.springframework.stereotype.Component;

@Component
public class PemKeyParse {
    public PrivateKey parsePrivateKey(byte[] pemBytes) {
        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pemBytes);
            return KeyFactory.getInstance(CryptoContants.RSA).generatePrivate(spec);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid private key format", e);
        }
    }

    public PublicKey parsePublicKey(byte[] pemBytes) {
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(pemBytes);
            return KeyFactory.getInstance(CryptoContants.RSA).generatePublic(spec);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid public key format", e);
        }
    }
}
