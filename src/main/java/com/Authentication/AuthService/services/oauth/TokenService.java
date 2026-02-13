package com.Authentication.AuthService.services.oauth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import com.Authentication.AuthService.config.CookieConfig;
import com.Authentication.AuthService.dto.RefreshTokenResponseDto;
import com.Authentication.AuthService.dto.TokenResponseDto;
import com.Authentication.AuthService.dto.OAuth.AuthorizationCodeData;
import com.Authentication.AuthService.entity.OAuth2Client;
import com.Authentication.AuthService.entity.OAuth2RefreshToken;
import com.Authentication.AuthService.exception.business.BusinessException;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {
    private final OAuthJwtService oAuthJwtService;
    private final CookieConfig cookieConfig;
    private final RefreshTokenService refreshTokenService;
    private final AuthorizationCodeService authorizationCodeService;

    private static final String CODE_CHALLENGE_METHOD_SUPPORT = "SHA-256";

    @Transactional
    public TokenResponseDto handleAuthorizationCodeFlow(
            String clientId,
            String code,
            String redirectUri,
            String state,
            String codeVerifier) {
        AuthorizationCodeData authCode = authorizationCodeService.validateAuthCode(code);
        if (authCode.isUsed()) {
            throw new BusinessException("CODE_USED", "Authorization code đã được sử dụng");
        }

        // Chú ý xem có nên verify nonce đã dử dụng ở đây không vì auth code cùng nonce
        // nên auth code mà used = true thì nonce cũng là used = true

        // Chú ý: về thuộc tính expiredAt do nếu sau này sử dụng redis sẽ có thời gian
        // sống là 5 phút bằng với expired time của auth code nên nếu sau này triển khai
        // redis thì có thể bỏ thuộc tính này và bỏ qua validate nàynàynày
        if (authCode.getExpiresAt().isBefore(Instant.now())) {
            throw new BusinessException("CODE_EXPIRED", "Authorization code đã hết hạn");
        }

        if (!authCode.getClientId().equals(clientId)) {
            throw new BusinessException("CLIENT_ID_MISMATCH", "Authorization Code không khớp với Client ID.");
        }

        if (!authCode.getRedirectUri().equals(redirectUri)) {
            throw new BusinessException("REDIRECT_URI_MISMATCH",
                    "Authorization Code không khớp với Redirect uri của Client.");
        }

        if (!authCode.getState().equals(state)) {
            throw new BusinessException("STATE_MISMATCH", "Authorization Code không khớp với State.");
        }

        validatePkceIfPresent(codeVerifier, authCode.getCodeChallenge(), authCode.getCodeChallengeMethod());

        // Đánh dấu auth code đã được sử dụng
        authorizationCodeService.markNonceAsUsed(code, authCode);

        String accessToken = oAuthJwtService.generateAccessToken(authCode.getUsername(),
                clientId, authCode.getScope());
        String idToken = oAuthJwtService.generateIdToken(authCode.getUsername(),
                clientId, authCode.getNonce());
        String refreshToken = oAuthJwtService.generateRefreshToken(authCode.getUsername(), clientId);

        return TokenResponseDto.builder()
                .accessToken(accessToken)
                .idToken(idToken)
                .refreshToken(refreshToken)
                .expiresIn(cookieConfig.getAccessTokenMaxAge())
                .scope(authCode.getScope())
                .build();
    }

    @Transactional
    public RefreshTokenResponseDto handleRefreshTokenFlow(OAuth2Client client, String refreshToken) {
        OAuth2RefreshToken token = refreshTokenService.validateRefreshToken(refreshToken, client.getClientId());

        String newAccessToken = oAuthJwtService.generateAccessToken(token.getUsername(), client.getClientId(),
                token.getScope());
        return RefreshTokenResponseDto.builder()
                .accessToken(newAccessToken)
                .expiresIn(cookieConfig.getAccessTokenMaxAge())
                .tokenType("Bearer")
                .refreshToken(refreshToken) // Gửi lại refresh token cũ --> Chú ý nếu dùng OAuth2.1 thì rotation
                .scope(token.getScope())
                .build();
    }

    private void validatePkceIfPresent(String codeVerifier, String codeChallenge, String codeChallengeMethod) {
        if (!StringUtils.hasText(codeChallenge)) {
            throw new BusinessException("CODE_CHALLENGE_NOT_FOUND", "Không tìm thấy Code challenge.");
        }
        String expectedChallenge = generateS256Challenge(codeVerifier);
        if (!codeChallenge.equals(expectedChallenge)) {
            throw new BusinessException("INVALID_CODE_VERIFIER", "Code verifier không khớp với Code challenge.");
        }
    }

    private String generateS256Challenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance(CODE_CHALLENGE_METHOD_SUPPORT);
            byte[] hashed = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getEncoder().withoutPadding().encodeToString(hashed);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}