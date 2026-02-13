package com.Authentication.AuthService.services.auth;

import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.Authentication.AuthService.config.CookieConfig;
import com.Authentication.AuthService.dto.Auth.RefreshTokenData;
import com.Authentication.AuthService.enums.RedisKeyPrefix;
import com.Authentication.AuthService.exception.business.BusinessException;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RedisTemplate<String, Object> redisTemplate;
    private final PasswordEncoder passwordEncoder;
    private final CookieConfig cookieConfig;

    public void saveRefreshTokenToRedis(String refreshToken, RefreshTokenData tokenData) {
        String refreshTokenHash = passwordEncoder.encode(refreshToken);
        String key = RedisKeyPrefix.REFRESH_TOKEN_AUTH.getPrefix() + refreshTokenHash;
        long ttl = cookieConfig.getRefreshTokenMaxAge() + 60 * 5; // Thêm 5 phút đề phòng trường hợp đồng bộ thời gian
        redisTemplate.opsForValue().set(key, tokenData, ttl, TimeUnit.SECONDS);
    }

    public RefreshTokenData getRefreshTokenDataFromRedis(String refreshToken) {
        String refreshTokenHash = passwordEncoder.encode(refreshToken);
        String key = RedisKeyPrefix.REFRESH_TOKEN_AUTH.getPrefix() + refreshTokenHash;
        Object obj = redisTemplate.opsForValue().get(key);
        if (obj == null) {
            throw new BusinessException("REFRESH_TOKEN_NOT_FOUND", "Refresh token không tồn tại trong hệ thống.", HttpStatus.UNAUTHORIZED);
        }
        return (RefreshTokenData) obj;
    }
}
