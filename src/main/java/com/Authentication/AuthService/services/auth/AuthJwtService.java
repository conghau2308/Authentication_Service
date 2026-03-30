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
import com.Authentication.AuthService.dto.jwts.AccessTokenClaims;
import com.Authentication.AuthService.dto.jwts.RefreshTokenClaims;
import com.Authentication.AuthService.exception.business.BusinessException;

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

    public String generateAccessToken(String userId, String email, String name) {
        log.debug("Generating access token for userId={}, email={}", userId, email);
        log.debug("Token max age (raw): {}", cookieConfig.getAccessTokenMaxAge());

        AccessTokenClaims claims = AccessTokenClaims.builder()
                .type(TOKEN_TYPE_ACCESS)
                .jti(generateUniqueTokenId(userId))
                .email(email)
                .name(name)
                .build();

        log.debug("Claims map: {}", claims.toClaimsMap()); // xem map có gì
        return createToken(claims.toClaimsMap(), userId, cookieConfig.getAccessTokenMaxAge() * 1000);
    }

    public String generateRefreshToken(String userId) {

        RefreshTokenClaims claims = RefreshTokenClaims.builder()
                .type(TOKEN_TYPE_REFRESH)
                .jti(generateUniqueTokenId(userId))
                .build();
        return createToken(claims.toClaimsMap(), userId, cookieConfig.getRefreshTokenMaxAge() * 1000);
    }

    private String generateUniqueTokenId(String userId) {
        String uuid = UUID.randomUUID().toString();
        Long nanoTime = System.nanoTime();
        int userIdHash = userId.hashCode();

        return String.format("%s-%d-%d", uuid, nanoTime, userIdHash);
    }

    private String createToken(Map<String, Object> claims, String subject, long expirationMillis) {
        try {
            Date now = new Date();
            Date expiryDate = new Date(now.getTime() + expirationMillis);

            // String jti = (String) claims.get("jti");

            return Jwts.builder()
                    .setSubject(subject)
                    .setIssuedAt(now)
                    .setExpiration(expiryDate)
                    .addClaims(claims)
                    .signWith(signingKey, SignatureAlgorithm.HS256)
                    .compact();
        } catch (Exception e) {
            log.error("Failed to create token for subject {}: {}", subject, e.getMessage(), e);
            throw new RuntimeException("Failed to create JWT token", e);
        }
    }

    private Claims parseToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private String getUserId(Claims claims) {
        return claims.getSubject();
    }

    private String getTokenType(Claims claims) {
        return claims.get("type", String.class);
    }

    private boolean isTokenExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }

    public boolean validateAccessToken(String token, String userid) {
        try {
            Claims claims = parseToken(token);

            return getUserId(claims).equals(userid)
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

    public String extractUserId(String token) {
        return parseToken(token).getSubject();
    }

    public Date extractExpiration(String token) {
        return parseToken(token).getExpiration();
    }
}