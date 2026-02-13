package com.Authentication.AuthService.services.oauth;

import java.time.Instant;
import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.Authentication.AuthService.dto.OAuth.RefreshTokenData;
import com.Authentication.AuthService.enums.RedisKeyPrefix;
import com.Authentication.AuthService.exception.business.BusinessException;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class RefreshTokenService {

    private final JwtService oAuthJwtService;
    private final PasswordEncoder passwordEncoder;
    private final RedisTemplate<String, Object> redisTemplate;

    /**
     * Revoke refresh token
     */
    public void revokeRefreshToken(String refreshToken) {
        RefreshTokenData tokenData = getRefreshTokenDataFromRedis(refreshToken);
        tokenData.setRevoked(true);
        tokenData.setRevokedAt(Instant.now());
        long ttl = tokenData.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond();
        if (ttl <= 0) {
            ttl = 60; // Nếu token đã hết hạn thì vẫn lưu trong redis thêm 1 phút để tránh lỗi
        }
        String refreshTokenHash = passwordEncoder.encode(refreshToken);
        String key = RedisKeyPrefix.REFRESH_TOKEN_OAUTH.getPrefix() + refreshTokenHash;
        redisTemplate.opsForValue().set(key, tokenData, ttl, TimeUnit.SECONDS);
        log.info("Refresh token đã bị revoke từ Redis.");
    }

    public RefreshTokenData validateRefreshToken(String refreshToken, String clientId) {
        RefreshTokenData token = getRefreshTokenDataFromRedis(refreshToken);
        // Chú ý xem thử có cần validate lại client id không do trong OAuthJwtService có
        // validate clientID trong cliams của token rồi
        if (!token.getClientId().equals(clientId)) {
            throw new BusinessException("REFRESH_TOKEN_MISMATCH", "Refresh token không được dùng cho Client ID này.",
                    HttpStatus.UNAUTHORIZED);
        }
        if (token.isRevoked()) {
            throw new BusinessException("TOKEN_REVOKED", "Refresh token đã bị thu hồi.", HttpStatus.UNAUTHORIZED);
        }
        oAuthJwtService.validateRefreshToken(refreshToken, clientId);
        return token;
    }

    // HIện chỉ lất refresh token từ redis để validate chứ chưa có xóa do đó cần xem
    // trường hợp lộ token
    private RefreshTokenData getRefreshTokenDataFromRedis(String refreshToken) {
        String refreshTokenHash = passwordEncoder.encode(refreshToken);
        String key = RedisKeyPrefix.REFRESH_TOKEN_OAUTH.getPrefix() + refreshTokenHash;
        Object value = redisTemplate.opsForValue().get(key);
        if (value == null) {
            throw new BusinessException("REFRESH_TOKEN_NOT_FOUND", "Refresh token đã hết hạn hoặc không tồn tại.",
                    HttpStatus.UNAUTHORIZED);
        }
        return (RefreshTokenData) value;
    }
}