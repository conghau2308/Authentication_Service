package com.Authentication.AuthService.services.oauth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.Authentication.AuthService.config.CookieConfig;
import com.Authentication.AuthService.dto.TokenResponseDto;
import com.Authentication.AuthService.dto.OAuth.AuthorizationCodeData;
import com.Authentication.AuthService.exception.business.BusinessException;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {
    private final JwtService jwtService;
    private final CookieConfig cookieConfig;
    private final RefreshTokenService refreshTokenService;
    private final AuthorizationCodeService authorizationCodeService;

    private static final String CODE_CHALLENGE_METHOD_SUPPORT = "SHA-256";

    public TokenResponseDto handleAuthorizationCodeFlow(
            String clientId,
            String code,
            String redirectUri,
            String state,
            String codeVerifier) {
        AuthorizationCodeData authCode = authorizationCodeService.validateAndDeleteAuthCode(code);

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

        String accessToken = jwtService.generateAccessToken(authCode.getUserId(),
                clientId, authCode.getScope());
        String idToken = jwtService.generateIdToken(authCode.getUserId(),
                clientId, authCode.getNonce());
        String refreshToken = refreshTokenService.generateAndSaveRefreshToken(authCode.getUserId(),
                authCode.getClientId(), authCode.getScope());

        return TokenResponseDto.builder()
                .accessToken(accessToken)
                .idToken(idToken)
                .refreshToken(refreshToken)
                .expiresIn(cookieConfig.getAccessTokenMaxAge())
                .scope(authCode.getScope())
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
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashed);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}