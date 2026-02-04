package com.Authentication.AuthService.services.oauth;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;

import org.springframework.stereotype.Service;

import com.Authentication.AuthService.dto.Jwks.JwksDto;
import com.Authentication.AuthService.dto.Jwks.JwksResponseDto;
import com.Authentication.AuthService.services.auth.crypto.RsaKeyManagerService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class JwksService {
    private final RsaKeyManagerService rsaKeyManagerService;

    public JwksResponseDto getJwks() {
        RSAPublicKey publicKey = (RSAPublicKey) rsaKeyManagerService.getPublicKey();

        JwksDto jwk = JwksDto.builder()
                .kty("RSA")
                .use("sig")
                .kid(rsaKeyManagerService.getKeyId())
                .alg("RS256")
                .n(encodeBase64Url(publicKey.getModulus()))
                .e(encodeBase64Url(publicKey.getPublicExponent()))
                .build();

        return JwksResponseDto.builder()
                .keys(List.of(jwk))
                .build();
    }

    /**
     * Encode BigInteger to Base64 URL (for JWK format)
     */
    private String encodeBase64Url(BigInteger value) {
        byte[] bytes = value.toByteArray();

        // Remove leading zero byte if present (Java adds it for positive numbers)
        if (bytes[0] == 0 && bytes.length > 1) {
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            bytes = tmp;
        }

        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
