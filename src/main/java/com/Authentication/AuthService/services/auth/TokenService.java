package com.Authentication.AuthService.services.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import com.Authentication.AuthService.dto.RefreshTokenResponseDto;
import com.Authentication.AuthService.dto.TokenResponseDto;
import com.Authentication.AuthService.entity.OAuth2Code;
import com.Authentication.AuthService.entity.OAuth2RefreshToken;
import com.Authentication.AuthService.repository.OAuth2CodeRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2CodeRepository authorizationCodeRepository;
    private final RefreshTokenService refreshTokenService;
    private final OAuthJwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    /**
     * Xử lý cả 2 grant_type: authorization_code và refresh_token
     */
    public Object exchangeCodeForTokens(
            String grantType,
            String clientId,
            String clientSecret,
            String code,
            String redirectUri,
            String state,
            String codeVerifier) throws IllegalArgumentException {

        // Validate grant_type
        if (!"authorization_code".equals(grantType) && !"refresh_token".equals(grantType)) {
            log.error("❌ Grant type không được hỗ trợ: {}", grantType);
            throw new IllegalArgumentException("unsupported_grant_type");
        }

        // Validate client
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            log.error("❌ Client không tồn tại: {}", clientId);
            throw new IllegalArgumentException("invalid_client_id");
        }

        // Validate client_secret (so sánh với hash)
        // String storedClientSecret = registeredClient.getClientSecret();
        // if (storedClientSecret == null || !passwordEncoder.matches(clientSecret, storedClientSecret)) {
        //     log.error("❌ Client secret không hợp lệ cho client: {}", clientId);
        //     throw new IllegalArgumentException("invalid_client_secret");
        // }

        // Nếu bắt buộc PKCE thì nhớ validate thêm code_verifier

        // Xử lý authorization_code
        if ("authorization_code".equals(grantType)) {
            return handleAuthorizationCodeFlow(registeredClient, code, redirectUri, state, codeVerifier);
        }

        // Xử lý refresh_token
        if ("refresh_token".equals(grantType)) {
            return handleRefreshTokenFlow(registeredClient, code); // code ở đây là refresh_token
        }

        throw new IllegalArgumentException("unsupported_grant_type");
    }

    /**
     * Xử lý Authorization Code Flow
     */
    @Transactional
    private TokenResponseDto handleAuthorizationCodeFlow(
            RegisteredClient registeredClient,
            String code,
            String redirectUri,
            String state,
            String codeVerifier) throws IllegalArgumentException {

        log.info("Xử lý Authorization Code Flow cho client: {}", registeredClient.getClientId());

        // Validate authorization code
        OAuth2Code authCode = authorizationCodeRepository.findByCode(code)
                .orElseThrow(() -> {
                    log.error("Authorization code không tồn tại: {}", code);
                    return new IllegalArgumentException("code_not_found");
                });

        if (authCode.isUsed()) {
            log.error("Authorization code đã được sử dụng: {}", code);
            throw new IllegalArgumentException("code_already_used");
        }

        if (authCode.isUsed() && authorizationCodeRepository.existsByNonce(authCode.getNonce())) {
            log.error("Nonce đã được sử dụng.");
            throw new IllegalArgumentException("nonce_used");
        }

        // nếu cần thì thêm thuộc tính isExpired
        if (authCode.getExpiresAt().isBefore(Instant.now())) {
            log.error("Authorization code đã hết hạn: {}", code);
            throw new IllegalArgumentException("code_expired");
        }

        if (!authCode.getClientId().equals(registeredClient.getClientId())) {
            log.error("Client ID không khớp với code");
            throw new IllegalArgumentException("client_id_mismatch");
        }

        if (redirectUri != null && !authCode.getRedirectUri().equals(redirectUri)) {
            log.error("Redirect URI không khớp");
            throw new IllegalArgumentException("redirect_uri_mismatch");
        }

        if (state != null && !authCode.getState().equals(state)) {
            log.error("State không khớp");
            throw new IllegalArgumentException("state_mismatch");
        }

        validatePkceIfPresent(authCode, codeVerifier);

        // Đánh dấu code đã sử dụng
        authCode.setUsed(true);
        authorizationCodeRepository.save(authCode);

        log.info("Authorization code đã được đánh dấu used: {}", code);

        // Tạo tokens
        String accessToken = jwtService.generateAccessToken(
                authCode.getUsername(),
                registeredClient.getClientId(),
                authCode.getScope());

        String idToken = jwtService.generateIdToken(
                authCode.getUsername(),
                registeredClient.getClientId(),
                authCode.getNonce());

        String refreshToken = refreshTokenService.generateRefreshToken(
                authCode.getUsername(),
                registeredClient.getClientId(),
                authCode.getScope());

        log.info("Tokens được tạo thành công cho user: {} (access_token, id_token, refresh_token)",
                authCode.getUsername());

        return TokenResponseDto.builder()
                .accessToken(accessToken)
                .idToken(idToken)
                .refreshToken(refreshToken)
                .expiresIn(jwtService.getAccessTokenExpirationInSeconds())
                .tokenType("Bearer")
                .scope(authCode.getScope())
                .build();
    }

    /**
     * Xử lý Refresh Token Flow
     */
    @Transactional
    private RefreshTokenResponseDto handleRefreshTokenFlow(
            RegisteredClient registeredClient,
            String refreshToken) throws IllegalArgumentException {

        log.info("Xử lý Refresh Token Flow cho client: {}", registeredClient.getClientId());

        // Validate refresh token
        OAuth2RefreshToken token = refreshTokenService.validateRefreshToken(
                refreshToken,
                registeredClient.getClientId());

        // Tạo access token mới
        String newAccessToken = jwtService.generateAccessToken(
                token.getUsername(),
                registeredClient.getClientId(),
                token.getScope());

        log.info("Access token mới được tạo từ refresh token cho user: {}", token.getUsername());

        return RefreshTokenResponseDto.builder()
                .accessToken(newAccessToken)
                .expiresIn(jwtService.getAccessTokenExpirationInSeconds())
                .tokenType("Bearer")
                .scope(token.getScope())
                .refreshToken(refreshToken) // Gửi lại refresh token cũ
                .build();
    }

    private void validatePkceIfPresent(OAuth2Code authCode, String codeVerifier) {
        if (!StringUtils.hasText(authCode.getCodeChallenge())) {
            return;
        }

        if (!StringUtils.hasText(codeVerifier)) {
            log.error("Thiếu code_verifier cho authorization code yêu cầu PKCE");
            throw new IllegalArgumentException("no_code_verifier_found");
        }

        String method = authCode.getCodeChallengeMethod();
        String expectedChallenge = switch (method == null ? "plain" : method.toUpperCase()) {
            case "S256" -> generateS256Challenge(codeVerifier);
            case "PLAIN" -> codeVerifier;
            default -> throw new IllegalArgumentException("unsupported_method");
        };

        if (!authCode.getCodeChallenge().equals(expectedChallenge)) {
            log.error("code_verifier không khớp với code_challenge đã lưu");
            throw new IllegalArgumentException("invalid_code_verifier");
        }
    }

    private String generateS256Challenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashed);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Không hỗ trợ SHA-256 cho PKCE", e);
        }
    }
}