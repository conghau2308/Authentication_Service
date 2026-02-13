package com.Authentication.AuthService.services.oauth;

import java.time.Instant;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.Authentication.AuthService.entity.OAuth2RefreshToken;
import com.Authentication.AuthService.exception.business.BusinessException;
import com.Authentication.AuthService.repository.OAuth2RefreshTokenRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class RefreshTokenService {

    private final OAuth2RefreshTokenRepository refreshTokenRepository;
    private final OAuthJwtService oAuthJwtService;

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

    @Transactional(readOnly = true)
    public OAuth2RefreshToken validateRefreshToken(String refreshToken, String clientId) {
        OAuth2RefreshToken token = refreshTokenRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new BusinessException("REFRESH_TOKEN_NOT_FOUND", "Refresh token đã hết hạn.",
                        HttpStatus.UNAUTHORIZED));
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
}