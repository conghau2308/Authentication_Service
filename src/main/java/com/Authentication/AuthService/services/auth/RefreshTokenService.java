package com.Authentication.AuthService.services.auth;

import java.time.Instant;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.Authentication.AuthService.entity.OAuth2RefreshToken;
import com.Authentication.AuthService.repository.OAuth2RefreshTokenRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class RefreshTokenService {

    private final OAuth2RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.refresh-token-expiration:86400000}")
    private Long refreshTokenExpiration;

    /**
     * Tạo refresh token mới
     */
    @Transactional
    public String generateRefreshToken(String username, String clientId, String scope) {
        String tokenValue = UUID.randomUUID().toString();

        Instant now = Instant.now();
        Instant expiresAt = now.plusMillis(refreshTokenExpiration);

        OAuth2RefreshToken refreshToken = OAuth2RefreshToken.builder()
                .refreshToken(tokenValue)
                .username(username)
                .clientId(clientId)
                .scope(scope)
                .issuedAt(now)
                .expiresAt(expiresAt)
                .revoked(false)
                .build();

        refreshTokenRepository.save(refreshToken);
        log.info("Refresh token được tạo cho user: {} client: {} expires at: {}",
                username, clientId, expiresAt);

        return tokenValue;
    }

    /**
     * Validate refresh token
     */
    @Transactional(readOnly = true)
    public OAuth2RefreshToken validateRefreshToken(String refreshToken, String clientId)
            throws IllegalArgumentException {

        log.info("Validating refresh token for client: {}", clientId);

        OAuth2RefreshToken token = refreshTokenRepository
                .findValidToken(refreshToken, clientId)
                .orElseThrow(() -> {
                    log.error("Refresh token không hợp lệ hoặc đã hết hạn hoặc không khớp client_id");
                    return new IllegalArgumentException("invalid_grant");
                });

        if (token.isRevoked()) {
            log.error("Refresh token đã bị revoke");
            throw new IllegalArgumentException("invalid_grant");
        }

        if (token.getExpiresAt().isBefore(Instant.now())) {
            log.error("Refresh token đã hết hạn - expiresAt: {}, now: {}",
                    token.getExpiresAt(), Instant.now());
            throw new IllegalArgumentException("invalid_grant");
        }

        log.info("Refresh token hợp lệ cho user: {}", token.getUsername());
        return token;
    }

    /**
     * Revoke refresh token
     */
    @Transactional
    public void revokeRefreshToken(String refreshToken) {
        refreshTokenRepository.findByRefreshToken(refreshToken)
                .ifPresent(token -> {
                    token.setRevoked(true);
                    token.setRevokedAt(Instant.now());
                    refreshTokenRepository.save(token);
                    log.info("Refresh token đã bị revoke cho user: {}", token.getUsername());
                });
    }

    /**
     * Revoke tất cả refresh token của user
     */
    @Transactional
    public void revokeAllRefreshTokensForUser(String username) {
        var tokens = refreshTokenRepository.findByUsernameAndRevokedFalse(username);
        tokens.forEach(token -> {
            token.setRevoked(true);
            token.setRevokedAt(Instant.now());
        });
        refreshTokenRepository.saveAll(tokens);
        log.info("Tất cả {} refresh token của user {} đã bị revoke", tokens.size(), username);
    }

    /**
     * Revoke tất cả refresh token của user cho một client cụ thể
     */
    @Transactional
    public void revokeRefreshTokensForUserAndClient(String username, String clientId) {
        var tokens = refreshTokenRepository.findByUsernameAndClientIdAndRevokedFalse(username, clientId);
        tokens.forEach(token -> {
            token.setRevoked(true);
            token.setRevokedAt(Instant.now());
        });
        refreshTokenRepository.saveAll(tokens);
        log.info("Tất cả {} refresh token của user {} cho client {} đã bị revoke",
                tokens.size(), username, clientId);
    }
}