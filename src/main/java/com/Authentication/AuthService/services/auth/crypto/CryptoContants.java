package com.Authentication.AuthService.services.auth.crypto;

public final class CryptoContants {
    private CryptoContants() {
    };

    public static final String RSA = "RSA";
    public static final String SHA_256 = "SHA-256";

    public static final String PEM_PRIVATE_HEADER = "-----BEGIN PRIVATE KEY-----";
    public static final String PEM_PRIVATE_FOOTER = "-----END PRIVATE KEY-----";

    public static final String PEM_PUBLIC_HEADER = "-----BEGIN PUBLIC KEY-----";
    public static final String PEM_PUBLIC_FOOTER = "-----END PUBLIC KEY-----";
}
