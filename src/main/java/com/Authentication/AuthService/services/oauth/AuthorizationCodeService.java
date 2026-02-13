package com.Authentication.AuthService.services.oauth;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import com.Authentication.AuthService.dto.OAuth.AuthorizationCodeData;
import com.Authentication.AuthService.exception.business.BusinessException;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthorizationCodeService {
    private final RedisTemplate<String, Object> redisTemplate;

    // Dùng để tạo chuỗi code ngẫu nhiên an toàn
    private static final SecureRandom secureRandom = new SecureRandom();
    // Dùng để encode code b64
    private static final Base64.Encoder base64Encoder = Base64.getEncoder().withoutPadding();

    private static final String AUTH_CODE_PREFIX = "auth_code:";

    @Value("${auth-code.code-expiration-second}")
    private int codeExpirationSecond;
    @Value("${auth-code.time-to-live-hour-redis}")
    private int timeToLiveHourRedis;

    private AuthorizationCodeData buildAuthorizationCode(String clientId, String username, String redirectUri,
            String scope, String state, String nonce, String codeChallenge, String codeChallengeMethod) {
        return AuthorizationCodeData.builder()
                .clientId(clientId)
                .username(username)
                .redirectUri(redirectUri)
                .scope(scope)
                .state(state)
                .nonce(nonce)
                .codeChallenge(codeChallenge)
                .codeChallengeMethod(codeChallengeMethod)
                .used(false)
                .expiresAt(Instant.now().plusSeconds(codeExpirationSecond))
                .build();
    }

    public String generateAuthorizationCode(String clientId, String username, String redirectUri,
            String scope, String state, String nonce, String codeChallenge, String codeChallengeMethod) {
        String code = generateSecureCodeString();
        AuthorizationCodeData authCode = buildAuthorizationCode(clientId, username, redirectUri, scope, state, nonce,
                codeChallenge, codeChallengeMethod);
        String key = AUTH_CODE_PREFIX + code;
        redisTemplate.opsForValue().set(key, authCode, timeToLiveHourRedis, TimeUnit.HOURS);
        return code;
    }

    private String generateSecureCodeString() {
        byte[] randomBytes = new byte[32]; // 32 bytes = 256 bits
        secureRandom.nextBytes(randomBytes);
        return base64Encoder.encodeToString(randomBytes);
    }

    // Validate auth code từ redis
    public AuthorizationCodeData validateAuthCode(String code) {
        String key = AUTH_CODE_PREFIX + code;
        Object value = redisTemplate.opsForValue().get(key);

        if (value == null) {
            throw new BusinessException("CODE_NOT_FOUND", "Không tồn tại Authorization code.", HttpStatus.NOT_FOUND);
        }
        return (AuthorizationCodeData) value;
    }

    public void markNonceAsUsed(String code, AuthorizationCodeData authCode) {
        String key = AUTH_CODE_PREFIX + code;
        authCode.setUsed(true);
        Long ttl = redisTemplate.getExpire(key, TimeUnit.HOURS);
        if (ttl != null && ttl > 0) {
            redisTemplate.opsForValue().set(key, authCode, ttl, TimeUnit.HOURS);
        }
    }
}
