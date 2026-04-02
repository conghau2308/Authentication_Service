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

    // ── Generate ──────────────────────────────────────────────

    public String generateAccessToken(String userId, String email, String name) {
        AccessTokenClaims claims = AccessTokenClaims.builder()
                .type(TOKEN_TYPE_ACCESS)
                .jti(generateUniqueTokenId(userId))
                .email(email)
                .name(name)
                .build();
        return createToken(claims.toClaimsMap(), userId, cookieConfig.getAccessTokenMaxAge() * 1000L);
    }

    public String generateRefreshToken(String userId) {
        RefreshTokenClaims claims = RefreshTokenClaims.builder()
                .type(TOKEN_TYPE_REFRESH)
                .jti(generateUniqueTokenId(userId))
                .build();
        return createToken(claims.toClaimsMap(), userId, cookieConfig.getRefreshTokenMaxAge() * 1000L);
    }

    // ── Validate ──────────────────────────────────────────────

    /**
     * Validate access token và trả về Claims nếu hợp lệ.
     * Throw ExpiredJwtException nếu hết hạn (để filter phân biệt).
     * Throw JwtException nếu token sai format/chữ ký.
     */
    public Claims validateAndExtractClaims(String token) {
        // parseToken tự throw ExpiredJwtException hoặc JwtException — không catch ở đây
        Claims claims = parseToken(token);

        String tokenType = getTokenType(claims);
        if (!TOKEN_TYPE_ACCESS.equals(tokenType)) {
            throw new JwtException("Invalid token type: " + tokenType);
        }

        return claims;
    }

    /**
     * Validate refresh token — dùng trong /auth/refresh endpoint.
     */
    public boolean validateRefreshToken(String token) {
        try {
            Claims claims = parseToken(token);
            return TOKEN_TYPE_REFRESH.equals(getTokenType(claims));
            // parseToken đã kiểm tra exp rồi, không cần isTokenExpired nữa
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Invalid refresh token: {}", e.getMessage());
            return false;
        }
    }

    // ── Extract ───────────────────────────────────────────────

    public String extractUserId(String token) {
        return parseToken(token).getSubject();
    }

    public Date extractExpiration(String token) {
        return parseToken(token).getExpiration();
    }

    // ── Private helpers ───────────────────────────────────────

    private Claims parseToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
        // Tự throw ExpiredJwtException nếu hết hạn
        // Tự throw JwtException nếu sai chữ ký / format
    }

    private String createToken(Map<String, Object> claims, String subject, long expirationMillis) {
        try {
            Date now = new Date();
            Date expiryDate = new Date(now.getTime() + expirationMillis);
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

    private String getTokenType(Claims claims) {
        return claims.get("type", String.class);
    }

    private String generateUniqueTokenId(String userId) {
        return String.format("%s-%d-%d",
                UUID.randomUUID(), System.nanoTime(), userId.hashCode());
    }
}