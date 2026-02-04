package com.Authentication.AuthService.services.auth.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface RsaKeyProvider {
    PublicKey getPublicKey();

    PrivateKey getPrivateKey();

    String getKeyId();
}
