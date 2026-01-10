package com.Authentication.AuthService.controller;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import com.Authentication.AuthService.dto.AuthenticateRequestDto;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.repository.OAuth2CodeRepository;
import com.Authentication.AuthService.repository.UserRepository;
import com.Authentication.AuthService.services.auth.AuthJwtService;
import com.Authentication.AuthService.services.auth.AuthorizationCodeService;
import com.Authentication.AuthService.services.auth.FaceAuthService;
import com.Authentication.AuthService.services.auth.OAuthJwtService;
import com.Authentication.AuthService.services.auth.RefreshTokenService;
import com.Authentication.AuthService.services.auth.TokenService;
import com.Authentication.AuthService.services.user.UserService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/oauth2")
@RequiredArgsConstructor
@Slf4j
// @CrossOrigin(origins = "http://localhost:3000") // Frontend URL
public class OAuth2AuthentizationController {

    private final RegisteredClientRepository registeredClientRepository;
    private final AuthorizationCodeService authorizationCodeService;
    private final FaceAuthService faceAuthService;
    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final OAuthJwtService jwtService;
    private final UserService userService;
    private final RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;
    private final OAuth2CodeRepository oAuth2CodeRepository;

    private final AuthJwtService authJwtService;

    private static final String OAUTH_ACCESS_TOKEN_COOKIE = "oauth_access_token"; // Khác tên!
    private static final String OAUTH_REFRESH_TOKEN_COOKIE = "oauth_refresh_token"; // Khác tên!
    private static final int OAUTH_ACCESS_TOKEN_MAX_AGE = 60 * 60; // 1 hour
    private static final int OAUTH_REFRESH_TOKEN_MAX_AGE = 7 * 24 * 60 * 60;

    /**
     * API 1: Validate OAuth parameters
     * Frontend gọi API này khi page load để validate trước khi hiển thị UI
     */
    @GetMapping("/authorize/validate")
    public ResponseEntity<Map<String, Object>> validateAuthorization(
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "scope", defaultValue = "openid profile") String scope,
            @RequestParam(value = "response_type", defaultValue = "code") String responseType,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "nonce", required = false) String nonce,
            @RequestParam(value = "code_challenge", required = false) String codeChallenge,
            @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod) {

        log.info("Validating OAuth request - client_id: {}, redirect_uri: {}", clientId, redirectUri);

        // 1. Validate response_type
        if (!"code".equals(responseType)) {
            log.error("Unsupported response_type: {}", responseType);
            return ResponseEntity
                    .badRequest()
                    .body(createValidationError("unsupported_response_type",
                            "Only response_type=code is supported", null, null));
        }

        // 2. Validate client_id
        RegisteredClient client = registeredClientRepository.findByClientId(clientId);
        if (client == null) {
            log.error("Invalid client_id: {}", clientId);
            return ResponseEntity
                    .badRequest()
                    .body(createValidationError("invalid_client",
                            "Client ID not found", null, null));
        }

        // 3. Validate redirect_uri (CRITICAL!)
        if (!client.getRedirectUris().contains(redirectUri)) {
            log.error("Invalid redirect_uri: {}. Registered: {}",
                    redirectUri, client.getRedirectUris());
            // KHÔNG trả redirect_uri nếu nó không hợp lệ (security!)
            return ResponseEntity
                    .badRequest()
                    .body(createValidationError("invalid_redirect_uri",
                            "The redirect URI is not registered for this client", null, null));
        }

        // 4. Validate scope
        String[] requestedScopes = scope.split(" ");
        for (String requestedScope : requestedScopes) {
            if (!client.getScopes().contains(requestedScope)) {
                log.error("Invalid scope: {}", requestedScope);
                // redirect_uri đã valid, có thể trả về để frontend redirect
                return ResponseEntity
                        .badRequest()
                        .body(createValidationError("invalid_scope",
                                "Scope '" + requestedScope + "' is not allowed",
                                redirectUri, state));
            }
        }

        // 5. Validate PKCE nếu có
        if (StringUtils.hasText(codeChallenge) && !StringUtils.hasText(codeChallengeMethod)) {
            codeChallengeMethod = "plain";
        }

        if (StringUtils.hasText(codeChallengeMethod) &&
                !isSupportedCodeChallengeMethod(codeChallengeMethod)) {
            log.error("Unsupported code_challenge_method: {}", codeChallengeMethod);
            return ResponseEntity
                    .badRequest()
                    .body(createValidationError("invalid_request",
                            "code_challenge_method must be 'plain' or 'S256'",
                            redirectUri, state));
        }

        // 6. Validate nonce nếu scope có "openid" (OIDC requirement)
        boolean hasOpenIdScope = scope.contains("openid");
        if (hasOpenIdScope && !StringUtils.hasText(nonce)) {
            log.warn("Missing nonce parameter for OpenID Connect request");
            // Nonce là recommended nhưng không bắt buộc theo spec
            // Nếu muốn bắt buộc, uncomment dòng dưới:
            // return ResponseEntity.badRequest()
            // .body(createValidationError("invalid_request",
            // "nonce is required for OpenID Connect requests",
            // redirectUri, state));
        }

        if (oAuth2CodeRepository.existsByNonce(nonce)) {
            log.error("Nonce is used: {}", nonce);
            return ResponseEntity
                    .badRequest()
                    .body(createValidationError("nonce_used",
                            "Nonce đã được sử dụng", null, null));
        }

        // 7. ALL VALIDATIONS PASSED
        log.info("OAuth validation successful for client: {}", client.getClientName());

        Map<String, Object> response = new HashMap<>();
        response.put("valid", true);
        response.put("client_name", client.getClientName());
        response.put("client_id", clientId);
        response.put("scopes", requestedScopes);

        return ResponseEntity.ok(response);
    }

    /**
     * API 2: Authenticate user với face recognition
     * Frontend gọi API này sau khi user nhập username và chụp ảnh
     */
    @PostMapping("/authenticate")
    public ResponseEntity<Map<String, Object>> authenticate(
            @RequestBody AuthenticateRequestDto request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        log.info("🔐 OAuth2 Authentication - username: {}, client_id: {}",
                request.getUsername(), request.getClientId());

        try {
            // 1. Validate client và redirect_uri
            RegisteredClient client = registeredClientRepository.findByClientId(request.getClientId());
            if (client == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(createAuthError("invalid_client", "Client ID không hợp lệ", null, null));
            }

            if (!client.getRedirectUris().contains(request.getRedirectUri())) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(createAuthError("invalid_request",
                                "Redirect URI không được đăng ký", null, null));
            }

            String username = null;
            boolean ssoUsed = false;

            // ============ CHECK OAUTH SSO COOKIE ============
            String oauthAccessToken = getCookieValue(httpRequest, OAUTH_ACCESS_TOKEN_COOKIE);

            if (oauthAccessToken != null && !oauthAccessToken.isEmpty()) {
                try {
                    log.info("🍪 Found OAuth SSO cookie, validating...");

                    String usernameFromToken = authJwtService.extractUsername(oauthAccessToken);

                    if (authJwtService.validateToken(oauthAccessToken, usernameFromToken)) {
                        Optional<User> userOpt = userRepository.findByUsername(usernameFromToken);

                        if (userOpt.isPresent()) {
                            username = usernameFromToken;
                            ssoUsed = true;
                            log.info("✅ OAuth SSO successful for user: {}", username);
                        }
                    }
                } catch (Exception e) {
                    log.warn("⚠️ OAuth SSO cookie invalid: {}", e.getMessage());
                    clearOAuthCookies(httpResponse);
                }
            }

            // ============ FACE AUTHENTICATION (nếu không có SSO) ============
            if (username == null) {
                log.info("🔑 No OAuth SSO, proceeding with face authentication...");

                // Validate inputs
                if (request.getUsername() == null || request.getUsername().trim().isEmpty()) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(createAuthError("invalid_request",
                                    "Username không được để trống",
                                    request.getRedirectUri(), request.getState()));
                }

                if (request.getImage_b64() == null || request.getImage_b64().isEmpty()) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(createAuthError("invalid_request",
                                    "Vui lòng gửi ảnh khuôn mặt",
                                    request.getRedirectUri(), request.getState()));
                }

                // Check user exists
                Optional<User> userOpt = userRepository.findByUsername(request.getUsername());
                if (userOpt.isEmpty()) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(createAuthError("access_denied", "User không tồn tại",
                                    request.getRedirectUri(), request.getState()));
                }

                User user = userOpt.get();

                if (user.getHelperData() == null || user.getKeyHash() == null) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(createAuthError("access_denied",
                                    "User chưa đăng ký dữ liệu khuôn mặt",
                                    request.getRedirectUri(), request.getState()));
                }

                // Verify face
                boolean authenticated = faceAuthService.verifyUser(
                        request.getUsername(),
                        request.getImage_b64(),
                        user.getHelperData(),
                        user.getKeyHash());

                if (!authenticated) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(createAuthError("access_denied",
                                    "Khuôn mặt không khớp",
                                    request.getRedirectUri(), request.getState()));
                }

                username = request.getUsername();

                // ⭐ SET OAUTH COOKIES sau khi face auth thành công
                String newAccessToken = authJwtService.generateAccessToken(
                        username, user.getEmail(), user.getName());
                String newRefreshToken = authJwtService.generateRefreshToken(username);

                setOAuthCookie(httpResponse, OAUTH_ACCESS_TOKEN_COOKIE,
                        newAccessToken, OAUTH_ACCESS_TOKEN_MAX_AGE);
                setOAuthCookie(httpResponse, OAUTH_REFRESH_TOKEN_COOKIE,
                        newRefreshToken, OAUTH_REFRESH_TOKEN_MAX_AGE);

                log.info("✅ Face auth successful, OAuth cookies set for: {}", username);
            }

            // Generate authorization code
            String authCode = authorizationCodeService.generateAuthorizationCode(
                    request.getClientId(), username, request.getRedirectUri(),
                    request.getScope(), request.getState(), request.getNonce(),
                    request.getCodeChallenge(), request.getCodeChallengeMethod());

            String redirectUrl = buildSuccessRedirectUrl(
                    request.getRedirectUri(), authCode, request.getState());

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Xác thực thành công");
            response.put("redirect_url", redirectUrl);
            response.put("sso_used", ssoUsed);

            return ResponseEntity.ok(response);

        } catch (FaceAuthService.PythonApiException e) {
            log.error("❌ Python API error: {}", e.getMessage());
            return ResponseEntity.status(mapPythonStatusCode(e.getStatusCode()))
                    .body(createAuthError("face_verification_error", e.getMessage(),
                            request.getRedirectUri(), request.getState()));

        } catch (Exception e) {
            log.error("❌ Error: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createAuthError("server_error", "Lỗi hệ thống: " + e.getMessage(),
                            request.getRedirectUri(), request.getState()));
        }
    }

    /**
     * Endpoint /token xử lý cả authorization_code và refresh_token grant types
     */
    @PostMapping("/token")
    public ResponseEntity<?> token(
            @RequestParam("grant_type") String grantType,
            @RequestParam("client_id") String clientId,
            @RequestParam("client_secret") String clientSecret,
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "code_verifier", required = false) String codeVerifier,
            @RequestParam(value = "refresh_token", required = false) String refreshToken,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri) {

        log.info("Nhận yêu cầu token - grant_type: {}, client_id: {}", grantType, clientId);

        try {
            // Validate grant_type
            if (!"authorization_code".equals(grantType) && !"refresh_token".equals(grantType)) {
                log.error("Grant type không được hỗ trợ: {}", grantType);
                return ResponseEntity
                        .status(HttpStatus.BAD_REQUEST)
                        .body(createErrorResponse("unsupported_grant_type",
                                "Chỉ hỗ trợ grant_type=authorization_code hoặc refresh_token"));
            }

            // Validate client_id
            if (clientId == null || clientId.isEmpty()) {
                log.error("client_id là bắt buộc");
                return ResponseEntity
                        .status(HttpStatus.BAD_REQUEST)
                        .body(createErrorResponse("invalid_request", "client_id là bắt buộc"));
            }

            // Validate client_secret
            if (clientSecret == null || clientSecret.isEmpty()) {
                log.error("client_secret là bắt buộc");
                return ResponseEntity
                        .status(HttpStatus.BAD_REQUEST)
                        .body(createErrorResponse("invalid_request", "client_secret là bắt buộc"));
            }

            // Kiểm tra parameter theo grant_type
            if ("authorization_code".equals(grantType)) {
                if (code == null || code.isEmpty()) {
                    log.error("code là bắt buộc cho grant_type=authorization_code");
                    return ResponseEntity
                            .status(HttpStatus.BAD_REQUEST)
                            .body(createErrorResponse("invalid_request", "code là bắt buộc"));
                }

                log.info("Xử lý authorization_code flow - code: {}", code);
                Object tokenResponse = tokenService.exchangeCodeForTokens(
                        grantType, clientId, clientSecret, code, redirectUri, state, codeVerifier);

                log.info("Token được tạo thành công cho client: {}", clientId);
                return ResponseEntity.ok(tokenResponse);
            }

            // Xử lý refresh_token
            if ("refresh_token".equals(grantType)) {
                if (refreshToken == null || refreshToken.isEmpty()) {
                    log.error("refresh_token là bắt buộc cho grant_type=refresh_token");
                    return ResponseEntity
                            .status(HttpStatus.BAD_REQUEST)
                            .body(createErrorResponse("invalid_request", "refresh_token là bắt buộc"));
                }

                log.info("Xử lý refresh_token flow");
                Object tokenResponse = tokenService.exchangeCodeForTokens(
                        grantType, clientId, clientSecret, refreshToken, redirectUri, null, null);

                log.info("Token được tạo thành công từ refresh_token cho client: {}", clientId);
                return ResponseEntity.ok(tokenResponse);
            }

            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(createErrorResponse("unsupported_grant_type", "Grant type không được hỗ trợ"));

        } catch (IllegalArgumentException e) {
            log.error("Lỗi validation token request: {}", e.getMessage());
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(createErrorResponse(e.getMessage(),
                            getErrorDescription(e.getMessage())));
        } catch (Exception e) {
            log.error("Lỗi không xác định khi tạo token: ", e);
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("server_error", "Lỗi server khi tạo token"));
        }
    }

    /**
     * Endpoint để revoke refresh token
     */
    @PostMapping("/revoke")
    public ResponseEntity<?> revokeToken(
            @RequestParam("token") String token,
            @RequestParam("token_type_hint") String tokenTypeHint,
            @RequestParam("client_id") String clientId,
            @RequestParam("client_secret") String clientSecret) {

        log.info("Nhận yêu cầu revoke token - token_type_hint: {}, client_id: {}",
                tokenTypeHint, clientId);

        try {
            // Validate client
            RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
            String storedClientSecret = registeredClient.getClientSecret();
            log.info("Client secret nhận {}, store {}", clientSecret, storedClientSecret);
            if (!passwordEncoder.matches(clientSecret, storedClientSecret)) {
                log.error("Invalid client_secret for client: {}", clientId);
                return ResponseEntity
                        .status(HttpStatus.UNAUTHORIZED)
                        .body(createErrorResponse("invalid_client", "Client authentication failed"));
            }

            if (token == null || token.isEmpty()) {
                log.error("Token is required");
                return ResponseEntity
                        .status(HttpStatus.BAD_REQUEST)
                        .body(createErrorResponse("invalid_request", "token is required"));
            }

            // Hiện tại chỉ hỗ trợ revoke refresh_token
            if (!"refresh_token".equals(tokenTypeHint)) {
                log.warn("token_type_hint không được hỗ trợ: {}", tokenTypeHint);
                return ResponseEntity.ok(new HashMap<>());
            }

            // Gọi service revoke
            refreshTokenService.revokeRefreshToken(token);

            log.info("Token đã được revoke thành công");
            return ResponseEntity.ok(new HashMap<>());

        } catch (Exception e) {
            log.error("Lỗi khi revoke token: ", e);
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("server_error", "Lỗi server khi revoke token"));
        }
    }

    /**
     * OIDC UserInfo Endpoint
     * GET /oauth2/userinfo
     * Header: Authorization: Bearer {access_token}
     */
    @GetMapping("/userinfo")
    public ResponseEntity<Map<String, Object>> getUserInfo(
            @RequestHeader("Authorization") String authorization) {

        try {
            // 1. Extract token từ header
            if (!authorization.startsWith("Bearer ")) {
                log.error("Invalid authorization header format");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(createErrorResponse("invalid_token", "Invalid authorization header"));
            }

            String accessToken = authorization.substring(7);

            // 2. Validate và decode access token
            Claims claims = jwtService.validateAccessToken(accessToken);
            String username = claims.getSubject();

            // 3. Lấy thông tin user từ database
            User user = userService.findByUsername(username);

            if (user == null) {
                log.error("User not found: {}", username);
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(createErrorResponse("user_not_found", "User not found"));
            }

            // 4. Trả về user info theo OIDC standard
            Map<String, Object> userInfo = new HashMap<>();
            userInfo.put("sub", user.getUsername());
            userInfo.put("user_id", user.getId().toString());
            userInfo.put("name", user.getName());
            userInfo.put("email", user.getEmail());
            userInfo.put("preferred_username", user.getUsername());

            // Optional claims
            // if (user.getPicture() != null) {
            // userInfo.put("picture", user.getPicture());
            // }

            log.info("UserInfo returned for user: {}", username);
            return ResponseEntity.ok(userInfo);

        } catch (JwtException e) {
            log.error("Invalid access token: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(createErrorResponse("invalid_token", "Access token is invalid or expired"));
        } catch (Exception e) {
            log.error("Error fetching user info: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("server_error", "Internal server error"));
        }
    }

    /**
     * OAuth Logout - Clear OAuth cookies only
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            HttpServletRequest request,
            HttpServletResponse response) {

        log.info("🚪 OAuth Logout request");

        String accessToken = getCookieValue(request, OAUTH_ACCESS_TOKEN_COOKIE);
        if (accessToken != null) {
            try {
                String username = authJwtService.extractUsername(accessToken);
                log.info("Logout OAuth session for user: {}", username);
            } catch (Exception e) {
                log.warn("Could not extract username");
            }
        }

        clearOAuthCookies(response);

        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("success", true);
        responseMap.put("message", "Đăng xuất OAuth thành công");

        return ResponseEntity.ok(responseMap);
    }

    // ==================== Helper Methods ====================

    /**
     * Tạo error response cho validation endpoint
     * Chỉ include redirect_uri nếu nó đã được validate
     */
    private Map<String, Object> createValidationError(
            String error,
            String errorDescription,
            String redirectUri,
            String state) {

        Map<String, Object> response = new HashMap<>();
        response.put("valid", false);
        response.put("error", error);
        response.put("error_description", errorDescription);

        // Chỉ include redirect info nếu redirect_uri hợp lệ
        if (redirectUri != null) {
            String redirectUrl = buildErrorRedirectUrl(redirectUri, error, errorDescription, state);
            response.put("redirect_url", redirectUrl);
            response.put("should_redirect", true);
        } else {
            response.put("should_redirect", false);
        }

        return response;
    }

    /**
     * Tạo error response cho authentication endpoint
     */
    private Map<String, Object> createAuthError(
            String error,
            String errorDescription,
            String redirectUri,
            String state) {

        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("error", error);
        response.put("error_description", errorDescription);

        if (redirectUri != null) {
            String redirectUrl = buildErrorRedirectUrl(redirectUri, error, errorDescription, state);
            response.put("redirect_url", redirectUrl);
        }

        return response;
    }

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

    /**
     * Build error redirect URL
     */
    private String buildErrorRedirectUrl(
            String redirectUri,
            String error,
            String errorDescription,
            String state) {

        StringBuilder url = new StringBuilder(redirectUri);
        url.append(redirectUri.contains("?") ? "&" : "?");
        url.append("error=").append(URLEncoder.encode(error, StandardCharsets.UTF_8));
        url.append("&error_description=").append(URLEncoder.encode(errorDescription, StandardCharsets.UTF_8));

        if (StringUtils.hasText(state)) {
            url.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8));
        }

        return url.toString();
    }

    private boolean isSupportedCodeChallengeMethod(String method) {
        return "plain".equalsIgnoreCase(method) || "S256".equalsIgnoreCase(method);
    }

    private Map<String, Object> createErrorResponse(String error, String errorDescription) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", error);
        errorResponse.put("error_description", errorDescription);
        return errorResponse;
    }

    /**
     * Get cookie value from request
     */
    private String getCookieValue(HttpServletRequest request, String name) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (name.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    /**
     * Set OAuth cookie with security flags
     */
    private void setOAuthCookie(HttpServletResponse response, String name,
            String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(true); // Set true in production (HTTPS)
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        cookie.setAttribute("SameSite", "None"); // Same as FaceAuth
        response.addCookie(cookie);

        log.debug("Set OAuth cookie: {} (maxAge: {}s)", name, maxAge);
    }

    /**
     * Clear OAuth cookies
     */
    private void clearOAuthCookies(HttpServletResponse response) {
        clearOAuthCookie(response, OAUTH_ACCESS_TOKEN_COOKIE);
        clearOAuthCookie(response, OAUTH_REFRESH_TOKEN_COOKIE);
        log.info("🗑️ OAuth cookies cleared");
    }

    /**
     * Clear single OAuth cookie
     */
    private void clearOAuthCookie(HttpServletResponse response, String name) {
        Cookie cookie = new Cookie(name, null);
        cookie.setHttpOnly(true);
        cookie.setSecure(false);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        cookie.setAttribute("SameSite", "None");
        response.addCookie(cookie);
    }

    private String getErrorDescription(String error) {
        return switch (error) {
            case "unsupported_grant_type" ->
                "Grant type không được hỗ trợ. Chỉ hỗ trợ authorization_code hoặc refresh_token";
            case "invalid_client_id" -> "Client ID không hợp lệ";
            case "invalid_client_secret" -> "Client Secret không hợp lệ";
            case "invalid_grant" ->
                "Authorization code hoặc refresh token không hợp lệ, đã hết hạn hoặc đã được sử dụng";
            case "code_not_found" -> "Authorization code không tồn tại";
            case "code_already_used" -> "Authorization code đã được sử dụng";
            case "code_expired" -> "Authorization code đã hết hạn";
            case "client_id_mismatch" -> "Client ID không khớp với code";
            case "redirect_uri_mismatch" -> "Redirect URI không khớp";
            case "state_mismatch" -> "State không khớp";
            case "invalid_request" -> "Request không hợp lệ, thiếu parameter bắt buộc";
            case "invalid_refresh_token" -> "Refresh token không hợp lệ hoặc đã hết hạn hoặc không khớp client_id";
            case "refresh_token_is_revoked" -> "Refresh token đã bị revoke";
            case "refresh_token_expired" -> "Refresh token đã hết hạn";
            case "no_code_verifier_found" -> "Thiếu code_verifier cho authorization code yêu cầu PKCE";
            case "unsupported_method" -> "Chỉ hỗ trợ challenge method S256";
            case "invalid_code_verifier" -> "code_verifier không khớp với code_challenge đã lưu";
            case "none_used" -> "Nonce đã được sử dụng.";
            default -> "Lỗi không xác định";
        };
    }

    /**
     * Helper method để map Python status code
     */
    private HttpStatus mapPythonStatusCode(int statusCode) {
        return switch (statusCode) {
            case 400 -> HttpStatus.BAD_REQUEST;
            case 404 -> HttpStatus.NOT_FOUND;
            case 500 -> HttpStatus.INTERNAL_SERVER_ERROR;
            default -> HttpStatus.BAD_REQUEST;
        };
    }
}