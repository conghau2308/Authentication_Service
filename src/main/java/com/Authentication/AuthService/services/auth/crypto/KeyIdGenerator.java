package com.Authentication.AuthService.services.auth.crypto;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Base64;

import org.springframework.stereotype.Component;

@Component
public class KeyIdGenerator {
    public String generate(PublicKey publicKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance(CryptoContants.SHA_256);
            return Base64.getEncoder().withoutPadding().encodeToString(digest.digest(publicKey.getEncoded()))
                    .substring(0, 16);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot generate key id", e);
        }
    }
}
