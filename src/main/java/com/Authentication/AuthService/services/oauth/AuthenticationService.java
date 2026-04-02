package com.Authentication.AuthService.services.oauth;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.Authentication.AuthService.dto.OAuth2ValidateClientResponseDto;
import com.Authentication.AuthService.dto.RefreshTokenResponseDto;
import com.Authentication.AuthService.dto.TokenResponseDto;
import com.Authentication.AuthService.dto.oauth.AuthorizeRequestDto;
import com.Authentication.AuthService.dto.oauth.AuthorizeResponseDto;
import com.Authentication.AuthService.dto.oauth.ConsentRequestDto;
import com.Authentication.AuthService.entity.OAuth2Client;
import com.Authentication.AuthService.entity.OAuth2ClientSecret;
import com.Authentication.AuthService.entity.OAuth2UserConsent;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.exception.business.BusinessException;
import com.Authentication.AuthService.repository.OAuth2ClientRepository;
import com.Authentication.AuthService.repository.OAuth2ClientSecretRepository;
import com.Authentication.AuthService.repository.OAuth2UserConsentRepository;
import com.Authentication.AuthService.services.cookies.CookiesService;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {
    private final OAuth2ClientRepository registeredClientRepository;
    private final CookiesService cookiesService;
    private final AuthorizationCodeService authorizationCodeService;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final OAuth2ClientSecretRepository clientSecretRepository;
    private final OAuth2UserConsentRepository userConsentRepository;

    @Transactional
    public OAuth2ValidateClientResponseDto validateParams(String clientId, String redirectUri, String scope,
            String responseType, String state,
            String nonce, String codeChallenge, String codeChallengeMethod) {
        if (clientId == null | clientId.isBlank()) {
            log.error("clientId is null");
            throw new BusinessException("INVALID_REQUEST", "Client ID không được để trống.");
        }
        if (scope == null | scope.isBlank()) {
            throw new BusinessException("INVALID_REQUEST", "Scope không được để trống.");
        }
        if (!"code".equals(responseType)) {
            log.error("unsupported response type");
            throw new BusinessException("UNSUPPORTED_RESPONSE_TYPE", "Chỉ hỗ trợ response_type=code.");
        }

        OAuth2Client client = registeredClientRepository.findByClientId(clientId);

        if (client == null) {
            log.error("client is null");
            throw new BusinessException("INVALID_CLIENT", "Không tìm thấy Client.");
        }

        if (client.getRedirectUri() == null | !client.getRedirectUri().contains(redirectUri)) {
            log.error("redirect uri khong hop le cho client");
            throw new BusinessException("INVALID_REDIRECT_URI", "Redirect uri không được đăng ký cho Client này.");
        }

        String[] requestedScopes = scope.trim().split("[\\s+]+");
        for (String requestedScope : requestedScopes) {
            if (!client.getScopes().contains(requestedScope)) {
                log.error("scope khong hop le: {}", requestedScope);
                throw new BusinessException("INVALID_SCOPE", "Scope '" + requestedScope + "' không được cho phép.");
            }
        }

        if (!StringUtils.hasText(codeChallenge) || !StringUtils.hasText(codeChallengeMethod)) {
            log.error("Code challenge method is required");
            throw new BusinessException("PKCE_REQUIRED",
                    "Code challenge và Code challenge method cho PKCE là bắt buộc.");
        }

        // Có thể tạo hàm để check khi support nhiều method khác
        if (!"S256".equals(codeChallengeMethod)) {
            log.error("Chi ho tro S256.");
            throw new BusinessException("UNSUPPORTED_CODE_CHALLENGE_METHOD",
                    "Không hõ trợ Code challenge method '" + codeChallengeMethod + "' này.");
        }

        // Nếu scope có openid thì phải có nonce do buộc hỗ trợ OIDC
        boolean hasOpenIdScope = scope.contains("openid");
        if (hasOpenIdScope && !StringUtils.hasText(nonce)) {
            log.error("Nonce la bat buoc");
            throw new BusinessException("NONCE_MISSED", "Nonce là bắt buộc cho OpenID Connect (OIDC).");
        }

        return OAuth2ValidateClientResponseDto.builder().clientName(client.getClientName()).clientIcon("chua co")
                .clientHomepageUrl("chua co").scopes(requestedScopes)
                .build();
    }

    @Transactional
    public AuthorizeResponseDto authorize(AuthorizeRequestDto request, User user) {
        OAuth2Client client = registeredClientRepository.findByClientId(request.getClient_id());
        if (client == null)
            throw new BusinessException("INVALID_CLIENT", "Không tìm thấy Client.");
        if (!client.getRedirectUri().contains(request.getRedirect_uri()))
            throw new BusinessException("INVALID_REDIRECT_URI", "Redirect uri không hợp lệ.");

        Optional<OAuth2UserConsent> consentOpt = userConsentRepository.findByUserIdAndClientId(user.getId(),
                client.getId());

        // Case 1: đã có consent VÀ scope khớp → tạo authCode luôn
        if (consentOpt.isPresent() && consentOpt.get().getGrantedScopes().equals(request.getScope())) {
            return buildRedirectResponse(request, user, client);
        }

        // Case 2: chưa có consent HOẶC scope thay đổi → yêu cầu consent
        List<String> pendingScopes = Arrays.asList(request.getScope().trim().split("[\\s+]+"));
        return AuthorizeResponseDto.builder()
                .consent_required(true)
                .pending_scopes(pendingScopes)
                .client_name(client.getClientName())
                .build();
    }

    @Transactional
    public AuthorizeResponseDto confirmConsent(ConsentRequestDto request, User user) {
        OAuth2Client client = registeredClientRepository.findByClientId(request.getClient_id());
        if (client == null)
            throw new BusinessException("INVALID_CLIENT", "Không tìm thấy Client.");

        // Upsert consent
        Optional<OAuth2UserConsent> consentOpt = userConsentRepository.findByUserIdAndClientId(user.getId(),
                client.getId());

        if (consentOpt.isPresent()) {
            // Cập nhật scope mới
            consentOpt.get().setGrantedScopes(request.getScope());
            userConsentRepository.save(consentOpt.get());
        } else {
            // Tạo mới
            userConsentRepository.save(OAuth2UserConsent.builder()
                    .user(user)
                    .client(client)
                    .grantedScopes(request.getScope())
                    .build());
        }

        // Tạo authCode và trả redirect_url
        String authCode = authorizationCodeService.generateAuthorizationCode(
                request.getClient_id(),
                user.getId().toString(),
                request.getRedirect_uri(),
                request.getScope(),
                request.getState(),
                request.getNonce(),
                request.getCode_challenge(),
                request.getCode_challenge_method());

        String redirectUrl = buildSuccessRedirectUrl(request.getRedirect_uri(), authCode, request.getState());

        return AuthorizeResponseDto.builder()
                .redirect_url(redirectUrl)
                .consent_required(false)
                .build();
    }

    // Trích ra helper để tránh duplicate code
    private AuthorizeResponseDto buildRedirectResponse(AuthorizeRequestDto request, User user, OAuth2Client client) {
        String authCode = authorizationCodeService.generateAuthorizationCode(
                request.getClient_id(),
                user.getId().toString(),
                request.getRedirect_uri(),
                request.getScope(),
                request.getState(),
                request.getNonce(),
                request.getCode_challenge(),
                request.getCode_challenge_method());

        String redirectUrl = buildSuccessRedirectUrl(request.getRedirect_uri(), authCode, request.getState());

        return AuthorizeResponseDto.builder()
                .redirect_url(redirectUrl)
                .consent_required(false)
                .build();
    }

    @Transactional
    public TokenResponseDto exchangeTokens(String grantType, String clientId, String clientSecret, String code,
            String codeVerifier,
            String state, String redirectUri) {
        if (!"authorization_code".equals(grantType)) {
            throw new BusinessException("UNSUPPORTED_GRANT_TYPE", "Chỉ hỗ trợ grant_type=authorization_code.");
        }

        if (clientId == null || clientId.isBlank()) {
            throw new BusinessException("INVALID_REQUEST", "Client ID là bắt buộc.");
        }

        if (clientSecret == null || clientSecret.isBlank()) {
            throw new BusinessException("INVALID_REQUEST", "Client Secret là bắt buộc.");
        }

        if (code == null || code.isBlank()) {
            throw new BusinessException("INVALID_REQUEST", "Authorization code là bắt buộc.");
        }

        if (codeVerifier == null || codeVerifier.isBlank()) {
            throw new BusinessException("INVALID_REQUEST", "Code verifier cho PKCE là bắt buộc.");
        }

        if (state == null || state.isBlank()) {
            throw new BusinessException("INVALID_REQUEST", "State là bắt buộc.");
        }

        if (redirectUri == null || redirectUri.isBlank()) {
            throw new BusinessException("INVALID_REQUEST", "Redirect Uri là bắt buộc.");
        }

        List<OAuth2ClientSecret> clientSecrets = clientSecretRepository.findByClientClientIdAndIsActiveTrue(clientId);
        if (clientSecrets.isEmpty()) {
            throw new BusinessException("INVALID_CLIENT_SECRET", "Client không có Client Secret hợp lệ.",
                    HttpStatus.UNAUTHORIZED);
        }

        boolean secretMatch = false;
        for (OAuth2ClientSecret clientSecretEntity : clientSecrets) {
            if (passwordEncoder.matches(clientSecret, clientSecretEntity.getSecretHash())) {
                secretMatch = true;
                break;
            }
        }

        if (!secretMatch) {
            throw new BusinessException("INVALID_CLIENT_SECRET", "Client Secret không khớp với Client.",
                    HttpStatus.UNAUTHORIZED);
        }
        return tokenService.handleAuthorizationCodeFlow(clientId, code, redirectUri, state, codeVerifier);
    }

    @Transactional
    public RefreshTokenResponseDto refreshToken(String grantType, String clientId, String clientSecret,
            String refreshToken) {
        if (!"refresh_code".equals(grantType)) {
            throw new BusinessException("UNSUPPORTED_GRANT_TYPE", "Chỉ hỗ trợ grant_type=refresh_code.");
        }

        if (clientId == null || clientId.isBlank()) {
            throw new BusinessException("INVALID_REQUEST", "Client ID là bắt buộc.");
        }

        if (clientSecret == null || clientSecret.isBlank()) {
            throw new BusinessException("INVALID_REQUEST", "Client Secret là bắt buộc.");
        }

        if (refreshToken == null || refreshToken.isBlank()) {
            throw new BusinessException("INVALID_REQUEST", "Refresh token là bắt buộc.");
        }

        OAuth2Client client = registeredClientRepository.findByClientId(clientId);

        if (client == null) {
            throw new BusinessException("INVALID_CLIENT", "Không tìm thấy Client.", HttpStatus.NOT_FOUND);
        }

        List<OAuth2ClientSecret> clientSecrets = clientSecretRepository.findByClientClientIdAndIsActiveTrue(clientId);
        if (clientSecrets.isEmpty()) {
            throw new BusinessException("INVALID_CLIENT_SECRET", "Client không có Client Secret hợp lệ.",
                    HttpStatus.UNAUTHORIZED);
        }
        boolean secretMatch = false;
        for (OAuth2ClientSecret clientSecretEntity : clientSecrets) {
            if (passwordEncoder.matches(clientSecret, clientSecretEntity.getSecretHash())) {
                secretMatch = true;
                break;
            }
        }

        if (!secretMatch) {
            throw new BusinessException("INVALID_CLIENT_SECRET", "Client Secret không khớp với Client.",
                    HttpStatus.UNAUTHORIZED);
        }

        return refreshTokenService.rotateEncryptedOpaqueToken(refreshToken, clientId);
    }

    @Transactional
    public void revoke(String token, String tokenTypeHint, String clientId, String clientSecret) {
        // Hiện tại chỉ hỗ trợ revoke theo refresh token, có thể mở rộng để revoke tất
        // cả token cho user nhưng hiện tại mỗi user chỉ có 1 refresh token
        if (!"refresh_token".equals(tokenTypeHint)) {
            throw new BusinessException("UNSUPPORTED_TOKEN_TYPE", "Chỉ hỗ trợ token_type_hint=refresh_token.");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new BusinessException("INVALID_REQUEST", "Client ID là bắt buộc.");
        }
        if (clientSecret == null || clientSecret.isBlank()) {
            throw new BusinessException("INVALID_REQUEST", "Client Secret là bắt buộc.");
        }
        List<OAuth2ClientSecret> clientSecrets = clientSecretRepository.findByClientClientIdAndIsActiveTrue(clientId);
        if (clientSecrets.isEmpty()) {
            throw new BusinessException("INVALID_CLIENT_SECRET", "Client không có Client Secret hợp lệ.",
                    HttpStatus.UNAUTHORIZED);
        }
        boolean secretMatch = false;
        for (OAuth2ClientSecret clientSecretEntity : clientSecrets) {
            if (passwordEncoder.matches(clientSecret, clientSecretEntity.getSecretHash())) {
                secretMatch = true;
                break;
            }
        }

        if (!secretMatch) {
            throw new BusinessException("INVALID_CLIENT_SECRET", "Client Secret không khớp với Client.",
                    HttpStatus.UNAUTHORIZED);
        }
        refreshTokenService.revokeRefreshToken(token);
    }

    @Transactional
    public void logout(String refreshToken, HttpServletResponse response) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new BusinessException("TOKEN_IS_NULL", "Vui lòng gửi kèm cookies đã cấp.", HttpStatus.UNAUTHORIZED);
        }

        cookiesService.clearAllCookies(response);
    }

    // Helper method

    /**
     * Build success redirect URL với authorization code
     */
    private String buildSuccessRedirectUrl(String redirectUri, String code, String state) {
        StringBuilder url = new StringBuilder(redirectUri);
        url.append(redirectUri.contains("?") ? "&" : "?");
        url.append("code=").append(URLEncoder.encode(code, StandardCharsets.UTF_8));

        if (StringUtils.hasText(state)) {
            url.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8));
        }

        return url.toString();
    }
}
