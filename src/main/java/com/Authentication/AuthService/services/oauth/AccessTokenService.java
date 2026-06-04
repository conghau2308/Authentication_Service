package com.Authentication.AuthService.services.oauth;

import java.time.Instant;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.Authentication.AuthService.config.CookieConfig;
import com.Authentication.AuthService.dto.oauth.AccessTokenData;
import com.Authentication.AuthService.enums.RedisKeyPrefix;
import com.Authentication.AuthService.exception.business.BusinessException;
import com.Authentication.AuthService.services.token.TokenCryptoService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AccessTokenService {
    private final RedisTemplate<String, Object> redisTemplate;
    private final PasswordEncoder passwordEncoder;
    private final CookieConfig cookieConfig;
    private final TokenCryptoService tokenCryptoService;

    public String generateAndSaveAccessToken(String userId, String clientId, String scope) {
        String accessToken = tokenCryptoService.generateSecureRandomToken(32);
        saveAccessTokenToRedis(accessToken, userId, clientId, scope);
        return accessToken;
    }

    private final ObjectMapper objectMapper;

    public AccessTokenData getAccessToken(String accessToken) {
        String key = RedisKeyPrefix.ACCESS_TOKEN_OAUTH.getPrefix() + tokenCryptoService.hashToken(accessToken);
        Object value = redisTemplate.opsForValue().get(key);
        if (value == null) {
            throw new BusinessException("INVALID_TOKEN", "Access Token đã hết hạn.", HttpStatus.UNAUTHORIZED);
        }
        return objectMapper.convertValue(value, AccessTokenData.class);
    }

    private void saveAccessTokenToRedis(String accessToken, String userId, String clientId, String scope) {
        String key = RedisKeyPrefix.ACCESS_TOKEN_OAUTH.getPrefix() + tokenCryptoService.hashToken(accessToken);
        long ttl = cookieConfig.getAccessTokenMaxAge() + 60 * 5;
        AccessTokenData tokenData = AccessTokenData.builder()
                .userId(userId)
                .clientId(clientId)
                .scope(scope)
                .expiresAt(Instant.now().plusSeconds(cookieConfig.getAccessTokenMaxAge()))
                .build();
        redisTemplate.opsForValue().set(key, tokenData, ttl, TimeUnit.SECONDS);
    }
}
