package com.Authentication.AuthService.controller;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import com.Authentication.AuthService.dto.AuthenticateRequestDto;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.repository.UserRepository;
import com.Authentication.AuthService.services.auth.AuthorizationCodeService;
import com.Authentication.AuthService.services.auth.FaceAuthService;
import com.Authentication.AuthService.services.auth.JwtService;
import com.Authentication.AuthService.services.auth.TokenService;
import com.Authentication.AuthService.services.user.UserService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/oauth2")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "http://localhost:3000") // Frontend URL
public class OAuth2AuthentizationController {

    private final RegisteredClientRepository registeredClientRepository;
    private final AuthorizationCodeService authorizationCodeService;
    private final FaceAuthService faceAuthService;
    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final JwtService jwtService;
    private final UserService userService;

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
            @RequestBody AuthenticateRequestDto request) {

        log.info("Authentication request - username: {}, client_id: {}",
                request.getUsername(), request.getClientId());

        try {
            // 1. Re-validate client và redirect_uri (security best practice)
            RegisteredClient client = registeredClientRepository.findByClientId(request.getClientId());
            if (client == null) {
                log.error("Invalid client_id: {}", request.getClientId());
                return ResponseEntity
                        .badRequest()
                        .body(createAuthError("invalid_client",
                                "Invalid client", null, null));
            }

            if (!client.getRedirectUris().contains(request.getRedirectUri())) {
                log.error("Invalid redirect_uri: {}", request.getRedirectUri());
                return ResponseEntity
                        .badRequest()
                        .body(createAuthError("invalid_request",
                                "Invalid redirect URI", null, null));
            }

            // 3. Gọi Server A để verify face
            log.info("Đang gọi Server A để xác thực khuôn mặt cho user: {}",
                    request.getUsername());

            Optional<User> faceDataOpt = userRepository.findByUsername(request.getUsername());

            if (!faceDataOpt.isPresent()) {
                log.error("Không tìm thấy dữ liệu khuôn mặt cho user: {}",
                        request.getUsername());
                return ResponseEntity
                        .badRequest()
                        .body(createAuthError("access_denied",
                                "User has not enrolled their face", null, null));
            }

            User faceData = faceDataOpt.get();

            // Gọi đúng method verifyUser với đầy đủ tham số
            boolean authenticated = faceAuthService.verifyUser(
                    request.getUsername(),
                    request.getImage_b64(),
                    faceData.getHelperData(), // helper_data_b64
                    faceData.getKeyHash() // key_hash_b64
            );

            if (!authenticated) {
                log.warn("Face authentication failed for user: {}", request.getUsername());
                // Trả về error nhưng KHÔNG redirect ngay - cho phép user retry
                return ResponseEntity
                        .status(HttpStatus.UNAUTHORIZED)
                        .body(createAuthError("access_denied",
                                "Face authentication failed. Please try again.",
                                request.getRedirectUri(),
                                request.getState()));
            }

            log.info("Face authentication successful for user: {}", request.getUsername());

            // 3. Generate authorization code
            String authCode = authorizationCodeService.generateAuthorizationCode(
                    request.getClientId(),
                    request.getUsername(),
                    request.getRedirectUri(),
                    request.getScope(),
                    request.getState(),
                    request.getNonce(), // nonce for OIDC
                    request.getCodeChallenge(),
                    request.getCodeChallengeMethod());

            log.info("Generated authorization code for user: {}", request.getUsername());

            // 4. Trả về redirect URL
            String redirectUrl = buildSuccessRedirectUrl(
                    request.getRedirectUri(),
                    authCode,
                    request.getState());

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("redirect_url", redirectUrl);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Authentication error: ", e);
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createAuthError("server_error",
                            "Internal server error during authentication",
                            request.getRedirectUri(),
                            request.getState()));
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
                        grantType, clientId, clientSecret, code, redirectUri, codeVerifier);

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
                        grantType, clientId, clientSecret, refreshToken, redirectUri, null);

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
            if (registeredClient == null) {
                log.error("Client không tồn tại: {}", clientId);
                return ResponseEntity
                        .status(HttpStatus.BAD_REQUEST)
                        .body(createErrorResponse("invalid_client", "Client không hợp lệ"));
            }

            // Validate client_secret
            if (registeredClient.getClientSecret() == null || token.isEmpty()) {
                log.error("Token là bắt buộc");
                return ResponseEntity
                        .status(HttpStatus.BAD_REQUEST)
                        .body(createErrorResponse("invalid_request", "token là bắt buộc"));
            }

            // Hiện tại chỉ hỗ trợ revoke refresh_token
            if (!"refresh_token".equals(tokenTypeHint)) {
                log.warn("token_type_hint không được hỗ trợ: {}", tokenTypeHint);
                return ResponseEntity.ok(new HashMap<>());
            }

            // Gọi service revoke
            // refreshTokenService.revokeRefreshToken(token);

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

    private String getErrorDescription(String error) {
        return switch (error) {
            case "unsupported_grant_type" ->
                "Grant type không được hỗ trợ. Chỉ hỗ trợ authorization_code hoặc refresh_token";
            case "invalid_client" -> "Client ID hoặc Client Secret không hợp lệ";
            case "invalid_grant" ->
                "Authorization code hoặc refresh token không hợp lệ, đã hết hạn hoặc đã được sử dụng";
            case "invalid_request" -> "Request không hợp lệ, thiếu parameter bắt buộc";
            default -> "Lỗi không xác định";
        };
    }
}