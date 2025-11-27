package com.Authentication.AuthService.controller;

import com.Authentication.AuthService.services.auth.RsaKeyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@Slf4j
public class JwksController {

    private final RsaKeyService rsaKeyService;

    @Value("${jwt.issuer:http://localhost:8080}")
    private String issuer;

    /**
     * JWKS Endpoint - Public key cho clients verify JWT
     * Endpoint chuẩn: /.well-known/jwks.json
     */
    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> jwks() {
        log.info("JWKS endpoint called");

        RSAPublicKey publicKey = (RSAPublicKey) rsaKeyService.getPublicKey();

        Map<String, Object> jwk = new HashMap<>();
        jwk.put("kty", "RSA"); // Key Type
        jwk.put("use", "sig"); // Public key use: signature
        jwk.put("kid", rsaKeyService.getKeyId()); // Key ID
        jwk.put("alg", "RS256"); // Algorithm

        // Modulus (n) - Base64 URL encode
        jwk.put("n", encodeBase64Url(publicKey.getModulus()));

        // Exponent (e) - Base64 URL encode
        jwk.put("e", encodeBase64Url(publicKey.getPublicExponent()));

        Map<String, Object> response = new HashMap<>();
        response.put("keys", List.of(jwk));

        return ResponseEntity.ok(response);
    }

    /**
     * OpenID Connect Discovery Endpoint
     * Endpoint chuẩn: /.well-known/openid-configuration
     */
    @GetMapping("/.well-known/openid-configuration")
    public ResponseEntity<Map<String, Object>> openidConfiguration() {
        log.info("OpenID Configuration endpoint called");

        Map<String, Object> config = new HashMap<>();
        config.put("issuer", issuer);
        config.put("authorization_endpoint", issuer + "/oauth2/authorize");
        config.put("token_endpoint", issuer + "/oauth2/token");
        config.put("userinfo_endpoint", issuer + "/oauth2/userinfo");
        config.put("jwks_uri", issuer + "/.well-known/jwks.json");
        config.put("end_session_endpoint", issuer + "/oauth2/logout");

        config.put("response_types_supported", List.of("code"));
        config.put("grant_types_supported", List.of("authorization_code", "refresh_token"));
        config.put("subject_types_supported", List.of("public"));
        config.put("id_token_signing_alg_values_supported", List.of("RS256"));
        config.put("token_endpoint_auth_methods_supported", List.of("client_secret_post"));
        config.put("code_challenge_methods_supported", List.of("plain", "S256"));

        config.put("scopes_supported", List.of("openid", "profile", "email"));
        config.put("claims_supported", List.of(
                "sub", "name", "email", "preferred_username", "user_id"));

        return ResponseEntity.ok(config);
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