package com.Authentication.AuthService.services.auth;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
public class JwtService {
    
    @Value("${jwt.secret:your-256-bit-secret-key-that-is-at-least-32-characters-long}")
    private String secret;
    
    @Value("${jwt.access-token-expiration:3600000}") // 1 hour default
    private Long accessTokenExpiration;
    
    @Value("${jwt.refresh-token-expiration:86400000}") // 24 hours default
    private Long refreshTokenExpiration;
    
    @Value("${jwt.issuer:auth-service}")
    private String issuer;
    
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }
    
    public String generateAccessToken(String username, String clientId, String scope) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", scope);
        claims.put("client_id", clientId);
        
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuer(issuer)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    
    public String generateIdToken(String username, String clientId, String nonce) {
        var builder = Jwts.builder()
                .setSubject(username)
                .setAudience(clientId)
                .setIssuer(issuer)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .claim("name", username)
                .claim("preferred_username", username);

        if (nonce != null && !nonce.isBlank()) {
            builder.claim("nonce", nonce);
        }

        return builder
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    
    public String generateRefreshToken(String username, String clientId) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuer(issuer)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpiration))
                .claim("client_id", clientId)
                .claim("token_type", "refresh")
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    
    public Long getAccessTokenExpirationInSeconds() {
        return accessTokenExpiration / 1000;
    }
}