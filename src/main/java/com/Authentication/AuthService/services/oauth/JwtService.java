package com.Authentication.AuthService.services.oauth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import com.Authentication.AuthService.config.CookieConfig;
import com.Authentication.AuthService.config.JwtSecretConfig;
import com.Authentication.AuthService.dto.OAuth.Jwts.OauthAccessTokenClaims;
import com.Authentication.AuthService.dto.OAuth.Jwts.OauthIdTokenClaims;
import com.Authentication.AuthService.dto.OAuth.Jwts.OauthRefreshTokenClaims;
import com.Authentication.AuthService.exception.business.BusinessException;
import com.Authentication.AuthService.services.auth.crypto.RsaKeyManagerService;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import javax.crypto.SecretKey;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwtService {
    private static final String TOKEN_TYPE_ACCESS = "access";
    private static final String TOKEN_TYPE_REFRESH = "refresh";
    private static final String TOKEN_TYPE_ID = "id";

    @Value("${jwt.issuer}")
    private String issuer;

    // Hiện tại đang gộp chung config expiration của cookie nghĩa là jwr cho user
    // trên trang chính và client (user) là như nhau. Nên có thể tách nếu sau này có
    // sự khác nhau của 2 loại tokens
    private final CookieConfig cookieConfig;
    private final RsaKeyManagerService rsaKeyManagerService;

    private final JwtSecretConfig jwtSecretConfig;
    private SecretKey signingKey;

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

    /*
     * Chú ý: Hiện tại có 2 cách thiết kế hệ thống:
     * 1. server-side nghĩa là client chỉ dùng access token và refresh token để lấy
     * infor user như profile, avatar, ... nên hệ thống lúc đó sẽ cấp AT và RT dạng
     * opaque chứ không phải là jwt (có ID token là dạng jwt) => aud của AT và RT
     * đều là IdP còn ID token là client_id. Ví dụ Google triển khai mô hình này
     * 2. client-side tức là AT, RT và ID token đều là jwt và Backend (Resource
     * server) client sẽ có thể verify các token này (nghĩa là tokens jwt được mã
     * hóa bất đối xứng) --> khi đó AT và RT có thể được client sử dụng mà không cần
     * tạo tokens khác còn trường hớp 1 thì phải cần. Lúc này aud của AT sẽ là
     * domain backend Client, RT là IdP và ID token là client_id
     * ==> Cần xem xét mô hình nào phù hợp nhất.
     */

    public String generateAccessToken(String userId, String clientId, String scope) {
        OauthAccessTokenClaims claims = OauthAccessTokenClaims.builder()
                .type(TOKEN_TYPE_ACCESS)
                .jti(generateUniqueTokenId(userId, clientId))
                .user_id(userId)
                .scope(scope)
                .client_id(clientId)
                .build();
        return createTokenSym(claims.toClaimsMap(), userId, cookieConfig.getAccessTokenMaxAge() * 1000);
    }

    public String generateRefreshToken(String username, String clientId) {

        OauthRefreshTokenClaims claims = OauthRefreshTokenClaims.builder()
                .type(TOKEN_TYPE_REFRESH)
                .jti(generateUniqueTokenId(username, clientId))
                .client_id(clientId)
                .build();
        return createTokenAsym(claims.toClaimsMap(), username, issuer, cookieConfig.getRefreshTokenMaxAge() * 1000);
    }

    public String generateIdToken(String username, String clientId, String nonce) {

        OauthIdTokenClaims claims = OauthIdTokenClaims.builder()
                .type(TOKEN_TYPE_ID)
                .jti(generateUniqueTokenId(username, clientId))
                .nonce(nonce)
                .auth_time(Instant.now().getEpochSecond())
                .preferred_username(username)
                .build();
        return createTokenAsym(claims.toClaimsMap(), username, clientId, cookieConfig.getAccessTokenMaxAge() * 1000);
    }

    private String generateUniqueTokenId(String user, String clientId) {
        String uuid = UUID.randomUUID().toString();
        int userHash = user.hashCode();
        int clientIdHash = clientId.hashCode();

        return String.format("%s-%d-%d", uuid, userHash, clientIdHash);
    }

    private String createTokenAsym(Map<String, Object> claims, String subject, String audience, long expirationMillis) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMillis);

        String jti = (String) claims.get("jti");

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setAudience(audience)
                .setIssuer(issuer)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .setId(jti)
                .setHeaderParam("kid", rsaKeyManagerService.getKeyId())
                .signWith(rsaKeyManagerService.getPrivateKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    private Claims parseTokenAsym(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(rsaKeyManagerService.getPublicKey())
                .requireIssuer(issuer)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private String createTokenSym(Map<String, Object> claims, String subject, long expirationMillis) {
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

    private Claims parseTokenSym(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private String getTokenType(Claims claims) {
        return claims.get("type", String.class);
    }

    private String getClientId(Claims claims) {
        return claims.get("client_id", String.class);
    }

    private String getUsername(Claims claims) {
        return claims.get("username", String.class);
    }

    private String getUserId(Claims claims) {
        return claims.get("user_id", String.class);
    }

    private String getScope(Claims claims) {
        return claims.get("scope", String.class);
    }

    private boolean isTokenExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }

    public void validateRefreshToken(String token, String clientId) {
        try {
            Claims claims = parseTokenAsym(token);
            if (!TOKEN_TYPE_REFRESH.equals(getTokenType(claims))) {
                throw new BusinessException("INVALID_TOKEN_TYPE", "Token type không hợp lệ.", HttpStatus.UNAUTHORIZED);
            }
            // Validate audience của refresh token là IdP (issuer)
            if (!claims.getAudience().equals(issuer)) {
                throw new BusinessException("INVALID_AUDIENCE", "Audience của refresh token là không hợp lệ.",
                        HttpStatus.UNAUTHORIZED);
            }
            if (!getClientId(claims).equals(clientId)) {
                throw new BusinessException("CLIENT_ID_MISMATCH", "Client ID không khớp trong Refresh token.",
                        HttpStatus.UNAUTHORIZED);
            }
            if (isTokenExpired(claims)) {
                throw new BusinessException("TOKEN_EXPIRED", "Refresh token đã hết hạn.", HttpStatus.UNAUTHORIZED);
            }
        } catch (JwtException ex) {
            log.warn("Invalid refresh token OAuth: {}", ex.getMessage());
            throw new BusinessException("INVALID_REFRESH_TOKEN", "Refresh token không hợp lệ.",
                    HttpStatus.UNAUTHORIZED);
        }
    }

    public void validateAccessToken(String token, String userId, String clientId, String scope) {
        try {
            Claims claims = parseTokenSym(token);
            if (!TOKEN_TYPE_ACCESS.equals(getTokenType(claims))) {
                throw new BusinessException("INVALID_TOKEN_TYPE", "Token type không hợp lệ.", HttpStatus.UNAUTHORIZED);
            }
            if (!getClientId(claims).equals(clientId)) {
                throw new BusinessException("CLIENT_ID_MISMATCH", "Client ID không khớp trong Access token.",
                        HttpStatus.UNAUTHORIZED);
            }
            if (!getUserId(claims).equals(userId)) {
                throw new BusinessException("USERNAME_MISMATCH", "Username không khớp trong Access token",
                        HttpStatus.UNAUTHORIZED);
            }
            if (!getScope(claims).equals(scope)) {
                throw new BusinessException("SCOPE_MISMATCH", "Scope không khớp trong Access token.");
            }
            if (isTokenExpired(claims)) {
                throw new BusinessException("TOKEN_EXPIRED", "Access token đã hết hạn.", HttpStatus.UNAUTHORIZED);
            }
        } catch (JwtException ex) {
            log.warn("Invalid access token OAuth: {}", ex.getMessage());
            throw new BusinessException("INVALID_ACCESS_TOKEN", "Access token không hợp lệ.");
        }
    }

    public Claims parseAndValidateAccessToken(String accessToken) {
        Claims claims = parseTokenSym(accessToken);
        if (!TOKEN_TYPE_ACCESS.equals(getTokenType(claims))) {
            throw new BusinessException("INVALID_TOKEN_TYPE", "Token type không hợp lệ.", HttpStatus.UNAUTHORIZED);
        }
        if (isTokenExpired(claims)) {
            throw new BusinessException("TOKEN_EXPIRED", "Access token đã hết hạn.", HttpStatus.UNAUTHORIZED);
        }
        return claims;
    }
}