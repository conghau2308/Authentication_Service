package com.Authentication.AuthService.services.oauth;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import com.Authentication.AuthService.config.CookieConfig;
import com.Authentication.AuthService.config.RefreshTokenOAuthEncryptionConfig;
import com.Authentication.AuthService.dto.RefreshTokenResponseDto;
import com.Authentication.AuthService.dto.oauth.RefreshTokenData;
import com.Authentication.AuthService.dto.oauth.RefreshTokenMetaData;
import com.Authentication.AuthService.enums.RedisKeyPrefix;
import com.Authentication.AuthService.exception.business.BusinessException;
import com.Authentication.AuthService.services.token.TokenCryptoService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service("oauthRefreshTokenService")
@Slf4j
@RequiredArgsConstructor
public class RefreshTokenService {
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder base64Decoder = Base64.getUrlDecoder();

    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12; // 96 bits
    private static final int GCM_TAG_LENGTH = 128; // 128 bits

    private final JwtService jwtService;
    private final RedisTemplate<String, Object> redisTemplate;
    private final ObjectMapper objectMapper;
    private final TokenCryptoService hashTokenService;
    private final CookieConfig cookieConfig;
    private final RefreshTokenOAuthEncryptionConfig refreshTokenOAuthEncryptionConfig;
    private final AccessTokenService accessTokenService;
    private SecretKey signingKey;

    @PostConstruct
    public void init() {
        this.signingKey = initializeSigningKey(refreshTokenOAuthEncryptionConfig.getSecret());
    }

    private SecretKey initializeSigningKey(String secret) {
        if (secret == null || secret.isEmpty()) {
            log.error("AES encryption secret is null or empty!");
            throw new IllegalStateException("AES encryption secret must be configured");
        }

        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);

        if (keyBytes.length < 32) {
            log.error("AES secret is too short: {} bytes. Required: minimum 32 bytes", keyBytes.length);
            throw new IllegalStateException(
                    "AES secret must be at least 32 bytes (256 bits). Current: " + keyBytes.length + " bytes");
        }
        return new SecretKeySpec(keyBytes, "AES");
    }

    public RefreshTokenData validateEncryptedRefreshToken(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new BusinessException("INVALID_REFRESH_TOKEN",
                    "Refresh Token không được để trống.", HttpStatus.BAD_REQUEST);
        }

        try {
            String familyToken = extractFamilyFromToken(refreshToken);
            RefreshTokenData tokenData = getRefreshTokenDataFromRedis(familyToken);

            if (tokenData.isRevoked()) {
                throw new BusinessException("REFRESH_TOKEN_REVOKED",
                        "Refresh Token đã bị thu hồi.", HttpStatus.UNAUTHORIZED);
            }
            if (tokenData.isExpired()) {
                throw new BusinessException("REFRESH_TOKEN_EXPIRED",
                        "Refresh Token đã hết hạn.", HttpStatus.UNAUTHORIZED);
            }

            String tokenHash = hashTokenService.hashToken(refreshToken);
            if (!tokenHash.equals(tokenData.getTokenHashed())) {
                throw new BusinessException("INVALID_REFRESHTOKEN",
                        "Refresh Token không hợp lệ.", HttpStatus.UNAUTHORIZED);
            }

            return tokenData;
        } catch (BusinessException e) {
            throw e; // Re-throw BusinessException
        } catch (Exception e) {
            log.error("Error validating refresh token", e);
            throw new BusinessException("TOKEN_VALIDATION_FAILED",
                    "Xác thực token thất bại.", HttpStatus.UNAUTHORIZED);
        }
    }

    public String generateEncryptedOpaqueToken(String existingFamily) {
        try {
            String familyId = existingFamily != null ? existingFamily : generateTokenFamily();
            RefreshTokenMetaData metaData = RefreshTokenMetaData.builder()
                    .tokenFamily(familyId)
                    .version(1)
                    .timestamp(Instant.now().getEpochSecond())
                    .build();
            String encryptedMetadata = encryptMetadata(metaData);
            String randomPart = generateSecureRandomToken(32);
            return encryptedMetadata + "." + randomPart;
        } catch (Exception e) {
            log.error("Error generating encrypted opaque token", e);
            throw new BusinessException("TOKEN_GENERATION_FAILED",
                    "Không thể tạo token.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public RefreshTokenResponseDto rotateEncryptedOpaqueToken(String oldToken, String clientId) {
        if (oldToken == null || oldToken.isBlank()) {
            throw new BusinessException("INVALID_REFRESH_TOKEN",
                    "Refresh Token không được để trống.", HttpStatus.BAD_REQUEST);
        }
        if (clientId == null || clientId.isBlank()) {
            throw new BusinessException("INVALID_CLIENT_ID",
                    "Client ID không được để trống.", HttpStatus.BAD_REQUEST);
        }

        try {
            String familyToken = extractFamilyFromToken(oldToken);
            RefreshTokenData refreshTokenData = getRefreshTokenDataFromRedis(familyToken);

            // Validate token state
            if (refreshTokenData.isRevoked()) {
                throw new BusinessException("TOKEN_REVOKED",
                        "Refresh token đã bị thu hồi.", HttpStatus.UNAUTHORIZED);
            }
            if (refreshTokenData.isExpired()) {
                throw new BusinessException("TOKEN_EXPIRED",
                        "Refresh token đã hết hạn.", HttpStatus.UNAUTHORIZED);
            }
            if (!refreshTokenData.getClientId().equals(clientId)) {
                throw new BusinessException("REFRESH_TOKEN_MISMATCH",
                        "Refresh token không được dùng cho Client ID này.",
                        HttpStatus.UNAUTHORIZED);
            }

            // Check for token reuse
            String oldTokenHash = hashTokenService.hashToken(oldToken);
            if (!oldTokenHash.equals(refreshTokenData.getTokenHashed())) {
                log.error("TOKEN REUSE DETECTED! Family: {}, User: {}, ClientId: {}",
                        familyToken, refreshTokenData.getUserId(), clientId);

                revokeTokenFamily(familyToken);

                throw new BusinessException("TOKEN_REUSE_DETECTED",
                        "Phát hiện sử dụng lại token. Token family đã bị thu hồi.",
                        HttpStatus.UNAUTHORIZED);
            }

            // Generate new tokens
            String newToken = generateEncryptedOpaqueToken(familyToken);
            updateFamilyRefreshTokenInRedis(refreshTokenData, familyToken, newToken);
            String newAccessToken = accessTokenService.generateAndSaveAccessToken(
                    refreshTokenData.getUserId(),
                    refreshTokenData.getClientId(),
                    refreshTokenData.getScope());

            return RefreshTokenResponseDto.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(newToken)
                    .expiresIn(cookieConfig.getAccessTokenMaxAge())
                    .build();

        } catch (BusinessException e) {
            throw e; // Re-throw BusinessException để giữ nguyên error code và message
        } catch (Exception e) {
            log.error("Unexpected error during token rotation", e);
            throw new BusinessException("TOKEN_ROTATION_FAILED",
                    "Không thể làm mới token.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public String generateAndSaveRefreshToken(String userId, String clientId, String scope) {
        if (userId == null || userId.isBlank()) {
            throw new BusinessException("INVALID_USER_ID",
                    "User ID không được để trống.", HttpStatus.BAD_REQUEST);
        }
        if (clientId == null || clientId.isBlank()) {
            throw new BusinessException("INVALID_CLIENT_ID",
                    "Client ID không được để trống.", HttpStatus.BAD_REQUEST);
        }

        try {
            String familyToken = generateTokenFamily();
            String refreshToken = generateEncryptedOpaqueToken(familyToken);
            saveRefreshTokenToRedis(userId, clientId, scope, familyToken, refreshToken);
            return refreshToken;
        } catch (BusinessException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error generating and saving refresh token for user: {}", userId, e);
            throw new BusinessException("TOKEN_GENERATION_FAILED",
                    "Không thể tạo Refresh Token", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public void revokeRefreshToken(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new BusinessException("INVALID_REFRESH_TOKEN",
                    "Refresh Token không được để trống.", HttpStatus.BAD_REQUEST);
        }

        try {
            String familyToken = extractFamilyFromToken(refreshToken);
            revokeTokenFamily(familyToken);
        } catch (BusinessException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error revoking refresh token", e);
            throw new BusinessException("TOKEN_REVOKE_FAILED",
                    "Thu hồi Refresh Token thất bại.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private void revokeTokenFamily(String familyToken) {
        String key = RedisKeyPrefix.FAMILY_REFRESH_TOKEN_OAUTH.getPrefix() + familyToken;
        Object value = redisTemplate.opsForValue().get(key);

        if (value != null) {
            RefreshTokenData tokenData;
            if (value instanceof java.util.LinkedHashMap) {
                tokenData = objectMapper.convertValue(value, RefreshTokenData.class);
            } else {
                tokenData = (RefreshTokenData) value;
            }
            tokenData.revoke();

            long ttl = tokenData.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond();
            if (ttl <= 0) {
                ttl = 60; // Nếu token đã hết hạn thì vẫn lưu thêm 1 phút
            }

            redisTemplate.opsForValue().set(key, tokenData, ttl, TimeUnit.SECONDS);
            log.info("Revoked token family: {}", familyToken);
        } else {
            log.warn("Attempted to revoke non-existent token family: {}", familyToken);
        }
    }

    private String encryptMetadata(RefreshTokenMetaData metaData) {
        try {
            String json = objectMapper.writeValueAsString(metaData);
            byte[] plainTextBytes = json.getBytes(StandardCharsets.UTF_8);

            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, signingKey, gcmParameterSpec);
            byte[] cipherText = cipher.doFinal(plainTextBytes);

            byte[] combined = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);

            return base64Encoder.encodeToString(combined);
        } catch (JsonProcessingException e) {
            log.error("Error serializing metadata", e);
            throw new BusinessException("METADATA_SERIALIZATION_ERROR",
                    "Lỗi xử lý metadata.", HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (Exception e) {
            log.error("Error encrypting metadata", e);
            throw new BusinessException("ENCRYPTION_ERROR",
                    "Lỗi mã hóa token.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private RefreshTokenMetaData decryptMetadata(String encryptedData) {
        try {
            byte[] combined = base64Decoder.decode(encryptedData);

            if (combined.length < GCM_IV_LENGTH) {
                throw new BusinessException("INVALID_TOKEN_FORMAT",
                        "Token có định dạng không hợp lệ.", HttpStatus.BAD_REQUEST);
            }

            byte[] iv = new byte[GCM_IV_LENGTH];
            byte[] cipherText = new byte[combined.length - GCM_IV_LENGTH];

            System.arraycopy(combined, 0, iv, 0, iv.length);
            System.arraycopy(combined, iv.length, cipherText, 0, cipherText.length);

            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, signingKey, gcmParameterSpec);
            byte[] plainTextBytes = cipher.doFinal(cipherText);

            String json = new String(plainTextBytes, StandardCharsets.UTF_8);
            return objectMapper.readValue(json, RefreshTokenMetaData.class);
        } catch (IllegalArgumentException e) {
            log.error("Invalid Base64 encoding", e);
            throw new BusinessException("INVALID_TOKEN_ENCODING",
                    "Token có mã hóa không hợp lệ.", HttpStatus.BAD_REQUEST);
        } catch (JsonProcessingException e) {
            log.error("Error deserializing metadata", e);
            throw new BusinessException("METADATA_DESERIALIZATION_ERROR",
                    "Lỗi đọc metadata.", HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            log.error("Error decrypting metadata", e);
            throw new BusinessException("DECRYPTION_ERROR",
                    "Lỗi giải mã token.", HttpStatus.UNAUTHORIZED);
        }
    }

    private String generateTokenFamily() {
        byte[] randomBytes = new byte[24];
        secureRandom.nextBytes(randomBytes);
        return "fam_" + base64Encoder.encodeToString(randomBytes);
    }

    private String generateSecureRandomToken(int numBytes) {
        byte[] randomBytes = new byte[numBytes];
        secureRandom.nextBytes(randomBytes);
        return base64Encoder.encodeToString(randomBytes);
    }

    private String extractFamilyFromToken(String token) {
        if (token == null || !token.contains(".")) {
            throw new BusinessException("INVALID_TOKEN_FORMAT",
                    "Refresh token có định dạng không hợp lệ.", HttpStatus.BAD_REQUEST);
        }

        String[] parts = token.split("\\.", 2);
        if (parts[0].isBlank()) {
            throw new BusinessException("INVALID_TOKEN_FORMAT",
                    "Token metadata không hợp lệ.", HttpStatus.BAD_REQUEST);
        }

        String encryptedMetadata = parts[0];
        RefreshTokenMetaData metaData = decryptMetadata(encryptedMetadata);
        return metaData.getTokenFamily();
    }

    private void updateFamilyRefreshTokenInRedis(RefreshTokenData tokenData, String familyToken,
            String refreshToken) {
        String key = RedisKeyPrefix.FAMILY_REFRESH_TOKEN_OAUTH.getPrefix() + familyToken;
        tokenData.setTokenHashed(hashTokenService.hashToken(refreshToken));

        long ttl = tokenData.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond() + 60 * 5;
        if (ttl > 0) {
            redisTemplate.opsForValue().set(key, tokenData, ttl, TimeUnit.SECONDS);
            log.debug("Updated token family in Redis: {}, TTL: {}s", familyToken, ttl);
        } else {
            log.warn("Token family {} has expired, TTL: {}s", familyToken, ttl);
        }
    }

    private void saveRefreshTokenToRedis(String userId, String clientId, String scope,
            String familyToken, String refreshToken) {
        String key = RedisKeyPrefix.FAMILY_REFRESH_TOKEN_OAUTH.getPrefix() + familyToken;
        long ttl = cookieConfig.getRefreshTokenMaxAge() + 60 * 5;

        RefreshTokenData tokenData = RefreshTokenData.builder()
                .tokenHashed(hashTokenService.hashToken(refreshToken))
                .userId(userId)
                .clientId(clientId)
                .scope(scope)
                .expiresAt(Instant.now().plusSeconds(cookieConfig.getRefreshTokenMaxAge()))
                .issuedAt(Instant.now())
                .build();

        redisTemplate.opsForValue().set(key, tokenData, ttl, TimeUnit.SECONDS);
        log.debug("Saved refresh token to Redis for user: {}, family: {}", userId, familyToken);
    }

    private RefreshTokenData getRefreshTokenDataFromRedis(String familyToken) {
        String key = RedisKeyPrefix.FAMILY_REFRESH_TOKEN_OAUTH.getPrefix() + familyToken;
        Object value = redisTemplate.opsForValue().get(key);

        if (value == null) {
            throw new BusinessException("REFRESH_TOKEN_NOT_FOUND",
                    "Không tìm thấy Refresh Token.", HttpStatus.UNAUTHORIZED);
        }

        if (value instanceof java.util.LinkedHashMap) {
            return objectMapper.convertValue(value, RefreshTokenData.class);
        }

        return (RefreshTokenData) value;
    }
}