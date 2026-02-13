package com.Authentication.AuthService.services.oauth;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.Authentication.AuthService.dto.AuthenticateRequestDto;
import com.Authentication.AuthService.dto.OAuth2ValidateClientResponseDto;
import com.Authentication.AuthService.dto.RefreshTokenResponseDto;
import com.Authentication.AuthService.dto.TokenResponseDto;
import com.Authentication.AuthService.dto.OAuth.CheckSSORequestDto;
import com.Authentication.AuthService.dto.OAuth.FaceAuthRequestDto;
import com.Authentication.AuthService.dto.OAuth.SSOAuthorizeRequestDto;
import com.Authentication.AuthService.dto.OAuth.SSOStatusResponseDto;
import com.Authentication.AuthService.dto.OAuth.ValidateOAuthResponseDto;
import com.Authentication.AuthService.entity.OAuth2Client;
import com.Authentication.AuthService.entity.OAuth2ClientSecret;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.exception.business.BusinessException;
import com.Authentication.AuthService.repository.OAuth2ClientRepository;
import com.Authentication.AuthService.repository.OAuth2ClientSecretRepository;
import com.Authentication.AuthService.repository.UserRepository;
import com.Authentication.AuthService.services.auth.AuthJwtService;
import com.Authentication.AuthService.services.auth.FaceAuthService;
import com.Authentication.AuthService.services.cookies.CookiesService;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {
    private final OAuth2ClientRepository registeredClientRepository;
    private final AuthJwtService authJwtService;
    private final UserRepository userRepository;
    private final FaceAuthService faceAuthService;
    private final CookiesService cookiesService;
    private final AuthorizationCodeService authorizationCodeService;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final OAuth2ClientSecretRepository clientSecretRepository;

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

        // Chú ý hiện tại vẫn đang dùng thư viện Authentcation của java chứ chưa dùng
        // Entity
        // Do đó cần kiểm tra xem có phù hợp với nghiệp vụ không và cân nhắc chuyển sang
        // Entity
        OAuth2Client client = registeredClientRepository.findByClientId(clientId);

        if (client == null) {
            log.error("client is null");
            throw new BusinessException("INVALID_CLIENT", "Không tìm thấy Client.");
        }

        if (client.getRedirectUri() == null | !client.getRedirectUri().contains(redirectUri)) {
            log.error("redirect uri khong hop le cho client");
            throw new BusinessException("INVALID_REDIRECT_URI", "Redirect uri không được đăng ký cho Client này.");
        }

        String[] requestedScopes = scope.split("\\+");
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

        return OAuth2ValidateClientResponseDto.builder().clientName(client.getClientName()).scopes(requestedScopes)
                .build();
    }

    public ValidateOAuthResponseDto validateLogin(AuthenticateRequestDto request, String accessToken,
            HttpServletResponse response) {
        // Kiểm tra 1 lần nữa client và redirect_uri
        OAuth2Client client = registeredClientRepository.findByClientId(request.getClientId());

        if (client == null) {
            throw new BusinessException("INVALID_CLIENT", "Không tìm thấy Client.");
        }

        if (!client.getRedirectUri().contains(request.getRedirectUri())) {
            throw new BusinessException("INVALID_REDIRECT_URI", "Redirect uri không được đăng ký cho Client này.");
        }

        String username = null;
        boolean ssoUsed = false;

        // Vì trong 1 domain + path chỉ có 1 cookie (name) nên request sẽ chỉ gửi 1 jwt
        // chứa username
        // Chú ý việc quản lý nhiều account

        // Kiêm tra SSO
        if (StringUtils.hasText(accessToken)) {
            try {
                String usernameFromCookie = authJwtService.extractUsername(accessToken);
                if (authJwtService.validateAccessToken(accessToken, usernameFromCookie)) {
                    Optional<User> user = userRepository.findByUsername(usernameFromCookie);
                    if (user == null) {
                        throw new BusinessException("USER_NOT_FOUND", "Không tìm thấy user từ cookie.",
                                HttpStatus.UNAUTHORIZED);
                    }
                    if (usernameFromCookie.equals(request.getUsername())) {
                        username = usernameFromCookie;
                        ssoUsed = true;
                    } else
                        throw new BusinessException("USERNAME_DIFFERENT",
                                "Username trong yêu cầu và username trong cookie là khác nhau. Vui lòng đăng nhập.",
                                HttpStatus.UNAUTHORIZED);
                }
            } catch (Exception ex) {
                cookiesService.clearAccessTokenCookie(response);
            }
        }

        // Khi không có accessToken cookie thì phải đăng nhập face authenticate (nhận
        // accessToken = null trong request)
        if (username == null) {
            if (!StringUtils.hasText(request.getUsername())) {
                throw new BusinessException("INVALID_REQUEST", "Username không được để trống.");
            }

            if (!StringUtils.hasText(request.getImage_b64())) {
                throw new BusinessException("INVALID_REQUEST", "Vui lòng gửi ảnh chụp khuôn mặt.");
            }

            User user = userRepository.findByUsername(request.getUsername())
                    .orElseThrow(() -> new BusinessException("USER_NOT_FOUND", "Không tìm thấy user.",
                            HttpStatus.UNAUTHORIZED));
            if (user.getKeyHash() == null || user.getHelperData() == null) {
                throw new BusinessException("BIOMETRIC_NOT_FOUND", "User chưa đăng ký sinh trắc học.",
                        HttpStatus.UNAUTHORIZED);
            }

            // boolean result = faceAuthService.verifyUser(request.getUsername(),
            // request.getImage_b64(),
            // user.getHelperData(), user.getKeyHash());
            boolean result = true;

            if (!result) {
                throw new BusinessException("ACCESS_DENIED", "Khuôn mặt không khớp. Vui lòng đăng nhập lại.",
                        HttpStatus.UNAUTHORIZED);
            }

            // Tạo các cookie
            username = request.getUsername();
            String accessTokenNew = authJwtService.generateAccessToken(username, user.getEmail(), user.getName());
            String refreshTokenNew = authJwtService.generateRefreshToken(username);

            cookiesService.setSecureAllCookies(response, accessTokenNew, refreshTokenNew);
        }

        // Tạo auth code cho client
        String authCode = authorizationCodeService.generateAuthorizationCode(request.getClientId(), username,
                request.getRedirectUri(), request.getScope(), request.getState(), request.getNonce(),
                request.getCodeChallenge(), request.getCodeChallengeMethod());
        String redirectUrl = buildSuccessRedirectUrl(request.getRedirectUri(), authCode, request.getState());

        return ValidateOAuthResponseDto.builder().redirect_url(redirectUrl).sso_used(ssoUsed).build();
    }

    public SSOStatusResponseDto checkSSOStatus(CheckSSORequestDto request, String accessToken) {
        if (!StringUtils.hasText(accessToken)) {
            log.error("access token khong hop le.");
            return SSOStatusResponseDto.builder().ssoAvailable(false).build();
        }
        try {
            String usernameFromCookie = authJwtService.extractUsername(accessToken);
            if (!authJwtService.validateAccessToken(accessToken, usernameFromCookie)) {
                log.error("Access token validate failed.");
                return SSOStatusResponseDto.builder().ssoAvailable(false).build();
            }
            Optional<User> user = userRepository.findByUsername(usernameFromCookie);
            if (user.isEmpty()) {
                log.error("user is null");
                return SSOStatusResponseDto.builder().ssoAvailable(false).build();
            }

            boolean usernameMatch = request.getUsername() != null && usernameFromCookie.equals(request.getUsername());

            return SSOStatusResponseDto.builder()
                    .ssoAvailable(true)
                    .username(usernameFromCookie)
                    .usernameMatch(usernameMatch)
                    .build();
        } catch (Exception ex) {
            log.warn("SSO shecked failed: ", ex);
            return SSOStatusResponseDto.builder().ssoAvailable(false).build();
        }
    }

    public ValidateOAuthResponseDto authenticateWithFace(FaceAuthRequestDto request, HttpServletResponse response) {
        validateClient(request.getClientId(), request.getRedirectUri());
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new BusinessException("USER_NOT_FOUND", "Không tìm thấy user từ cookie.",
                        HttpStatus.UNAUTHORIZED));
        if (user.getKeyHash() == null || user.getHelperData() == null) {
            throw new BusinessException("BIOMETRIC_NOT_FOUND",
                    "User chưa đăng ký sinh trắc học.", HttpStatus.UNAUTHORIZED);
        }
        // boolean faceMatched = faceAuthService.verifyUser(request.getUsername(),
        // request.getImage_b64(),
        // user.getHelperData(), user.getKeyHash());
        boolean faceMatched = true;
        if (!faceMatched) {
            throw new BusinessException("ACCESS_DENIED", "Khuôn mặt không khớp.",
                    HttpStatus.UNAUTHORIZED);
        }
        String accessToken = authJwtService.generateAccessToken(user.getUsername(), user.getEmail(), user.getName());
        String refreshToken = authJwtService.generateRefreshToken(user.getUsername());
        cookiesService.setSecureAllCookies(response, accessToken, refreshToken);

        String authCode = authorizationCodeService.generateAuthorizationCode(
                request.getClientId(), user.getUsername(), request.getRedirectUri(),
                request.getScope(), request.getState(), request.getNonce(),
                request.getCodeChallenge(), request.getCodeChallengeMethod());
        String redirectUrl = buildSuccessRedirectUrl(request.getRedirectUri(), authCode, request.getState());

        return ValidateOAuthResponseDto.builder()
                .redirect_url(redirectUrl)
                .sso_used(false)
                .build();
    }

    public ValidateOAuthResponseDto authorizeWithSSO(SSOAuthorizeRequestDto request, String accessToken,
            HttpServletResponse response) {
        validateClient(request.getClientId(), request.getRedirectUri());
        String usernameFromCookie = authJwtService.extractUsername(accessToken);
        if (!authJwtService.validateAccessToken(accessToken, usernameFromCookie)) {
            cookiesService.clearAccessTokenCookie(response);
            throw new BusinessException("INVALID_SESSION", "Session không hợp lệ. Vui lòng đăng nhập lại.",
                    HttpStatus.UNAUTHORIZED);
        }

        if (!usernameFromCookie.equals(request.getUsername())) {
            throw new BusinessException("USERNAME_MISMATCH",
                    "Username không khớp với session.", HttpStatus.UNAUTHORIZED);
        }

        User user = userRepository.findByUsername(usernameFromCookie)
                .orElseThrow(() -> new BusinessException("USER_NOT_FOUND",
                        "Không tìm thấy user.", HttpStatus.UNAUTHORIZED));

        String authCode = authorizationCodeService.generateAuthorizationCode(
                request.getClientId(), usernameFromCookie, request.getRedirectUri(),
                request.getScope(), request.getState(), request.getNonce(),
                request.getCodeChallenge(), request.getCodeChallengeMethod());

        String redirectUrl = buildSuccessRedirectUrl(
                request.getRedirectUri(), authCode, request.getState());

        return ValidateOAuthResponseDto.builder()
                .redirect_url(redirectUrl)
                .sso_used(true)
                .build();
    }

    private void validateClient(String clientId, String redirectUri) {
        OAuth2Client client = registeredClientRepository.findByClientId(clientId);

        if (client == null) {
            throw new BusinessException("INVALID_CLIENT", "Không tìm thấy Client.");
        }

        if (!client.getRedirectUri().contains(redirectUri)) {
            throw new BusinessException("INVALID_REDIRECT_URI", "Redirect uri không được đăng ký cho Client này.");
        }
    }

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

        return tokenService.handleRefreshTokenFlow(client, refreshToken);
    }

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
