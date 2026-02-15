package com.Authentication.AuthService.services.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import com.Authentication.AuthService.config.CookieConfig;
import com.Authentication.AuthService.config.JwtSecretConfig;
import com.Authentication.AuthService.dto.Jwts.AccessTokenClaims;
import com.Authentication.AuthService.dto.Jwts.RefreshTokenClaims;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthJwtService {

    private SecretKey signingKey;

    private final CookieConfig cookieConfig;
    private final JwtSecretConfig jwtSecretConfig;

    private static final String TOKEN_TYPE_ACCESS = "access";
    private static final String TOKEN_TYPE_REFRESH = "refresh";

    @PostConstruct
    public void init() {
        this.signingKey = initializeSigningKey(jwtSecretConfig.getSecret());
    }

    private SecretKey initializeSigningKey(String secret) {
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);

        if (keyBytes.length < 32) {
            log.warn("Secret key is too short, generating a secure key");
            return Keys.secretKeyFor(SignatureAlgorithm.HS256);
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateAccessToken(String username, String email, String name) {

        AccessTokenClaims claims = AccessTokenClaims.builder()
                .type(TOKEN_TYPE_ACCESS)
                .jti(generateUniqueTokenId(username))
                .email(email)
                .name(name)
                .build();
        return createToken(claims.toClaimsMap(), username, cookieConfig.getAccessTokenMaxAge() * 1000);
    }

    public String generateRefreshToken(String username) {

        RefreshTokenClaims claims = RefreshTokenClaims.builder()
                .type(TOKEN_TYPE_REFRESH)
                .jti(generateUniqueTokenId(username))
                .build();
        return createToken(claims.toClaimsMap(), username, cookieConfig.getRefreshTokenMaxAge() * 1000);
    }

    private String generateUniqueTokenId(String username) {
        String uuid = UUID.randomUUID().toString();
        Long nanoTime = System.nanoTime();
        int usernameHash = username.hashCode();

        return String.format("%s-%d-%d", uuid, nanoTime, usernameHash);
    }

    private String createToken(Map<String, Object> claims, String subject, long expirationMillis) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMillis);

        String jti = (String) claims.get("jti");

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .setId(jti)
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    private Claims parseToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private String getUsername(Claims claims) {
        return claims.getSubject();
    }

    private String getTokenType(Claims claims) {
        return claims.get("type", String.class);
    }

    private boolean isTokenExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }

    public boolean validateAccessToken(String token, String username) {
        try {
            Claims claims = parseToken(token);

            return getUsername(claims).equals(username)
                    && getTokenType(claims).equals(TOKEN_TYPE_ACCESS)
                    && !isTokenExpired(claims);
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Invalid access token: {}", e.getMessage());
            return false;
        }
    }

    public boolean validateRefreshToken(String token) {
        try {
            Claims claims = parseToken(token);

            return getTokenType(claims).equals(TOKEN_TYPE_REFRESH)
                    && !isTokenExpired(claims);
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Invalid refresh token: {}", e.getMessage());
            return false;
        }
    }

    public String extractUsername(String token) {
        return parseToken(token).getSubject();
    }

    public Date extractExpiration(String token) {
        return parseToken(token).getExpiration();
    }
}