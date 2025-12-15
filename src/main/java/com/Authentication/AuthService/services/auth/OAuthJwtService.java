package com.Authentication.AuthService.services.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.services.user.UserService;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuthJwtService {

    private final RsaKeyService rsaKeyService;
    private final UserService userService; // ✅ Inject UserService

    @Value("${jwt.access-token-expiration:3600000}") // 1 hour default
    private Long accessTokenExpiration;

    @Value("${jwt.refresh-token-expiration:86400000}") // 24 hours default
    private Long refreshTokenExpiration;

    @Value("${jwt.issuer:http://localhost:8080}")
    private String issuer;

    /**
     * ✅ Generate Access Token với RS256
     * sub = username, user_id = stable ID
     */
    public String generateAccessToken(String username, String clientId, String scope) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", scope);
        claims.put("client_id", clientId);

        // ✅ CRITICAL: Thêm user_id (stable identifier)
        User user = userService.findByUsername(username);
        if (user != null) {
            claims.put("user_id", user.getId().toString());

            // Optional: Thêm email nếu có
            if (user.getEmail() != null) {
                claims.put("email", user.getEmail());
            }

            // Optional: Thêm name nếu có
            if (user.getName() != null) {
                claims.put("name", user.getName());
            }
        } else {
            log.warn("⚠️ User not found for username: {} - user_id will be missing", username);
        }

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username) // ✅ sub = username (có thể thay đổi)
                .setIssuer(issuer)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .setHeaderParam("kid", rsaKeyService.getKeyId())
                .signWith(rsaKeyService.getPrivateKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    /**
     * ✅ Generate ID Token với RS256
     * sub = username, user_id = stable ID
     */
    public String generateIdToken(String username, String clientId, String nonce) {
        // ✅ Query user từ database
        User user = userService.findByUsername(username);

        var builder = Jwts.builder()
                .setSubject(username) // ✅ sub = username
                .setAudience(clientId)
                .setIssuer(issuer)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .claim("preferred_username", username)
                .setHeaderParam("kid", rsaKeyService.getKeyId());

        // ✅ Add claims từ database
        if (user != null) {
            builder.claim("user_id", user.getId().toString());

            if (user.getName() != null) {
                builder.claim("name", user.getName());
            }

            if (user.getEmail() != null) {
                builder.claim("email", user.getEmail());
            }
        } else {
            log.warn("⚠️ User not found for username: {} - user_id will be missing", username);
        }

        if (nonce != null && !nonce.isBlank()) {
            builder.claim("nonce", nonce);
        }

        return builder
                .signWith(rsaKeyService.getPrivateKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    /**
     * Generate Refresh Token với RS256
     */
    public String generateRefreshToken(String username, String clientId) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuer(issuer)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpiration))
                .claim("client_id", clientId)
                .claim("token_type", "refresh")
                .setHeaderParam("kid", rsaKeyService.getKeyId())
                .signWith(rsaKeyService.getPrivateKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    public Long getAccessTokenExpirationInSeconds() {
        return accessTokenExpiration / 1000;
    }

    /**
     * Validate và parse access token với RS256
     */
    public Claims validateAccessToken(String token) throws JwtException {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(rsaKeyService.getPublicKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            log.error("Access token expired: {}", e.getMessage());
            throw new JwtException("Access token expired");
        } catch (JwtException e) {
            log.error("Invalid access token: {}", e.getMessage());
            throw new JwtException("Invalid access token");
        }
    }

    /**
     * Validate và parse refresh token với RS256
     */
    public Claims validateRefreshToken(String token) throws JwtException {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(rsaKeyService.getPublicKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // Verify token type
            if (!"refresh".equals(claims.get("token_type"))) {
                throw new JwtException("Not a refresh token");
            }

            return claims;
        } catch (ExpiredJwtException e) {
            log.error("Refresh token expired: {}", e.getMessage());
            throw new JwtException("Refresh token expired");
        } catch (JwtException e) {
            log.error("Invalid refresh token: {}", e.getMessage());
            throw new JwtException("Invalid refresh token");
        }
    }

    /**
     * Extract username from token without validation
     */
    public String extractUsername(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(rsaKeyService.getPublicKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return claims.getSubject();
        } catch (Exception e) {
            return null;
        }
    }
}