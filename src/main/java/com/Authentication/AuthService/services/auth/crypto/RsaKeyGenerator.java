package com.Authentication.AuthService.services.auth.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import org.springframework.stereotype.Component;

@Component
public class RsaKeyGenerator {
    public KeyPair generate(int KeySize) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(CryptoContants.RSA);
            generator.initialize(KeySize);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA algorithm not available", e);
        }
    }
}
