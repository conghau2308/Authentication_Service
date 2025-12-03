package com.Authentication.AuthService.controller;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.Authentication.AuthService.dto.FaceAuthLoginRequestDto;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.repository.UserRepository;
import com.Authentication.AuthService.services.auth.AuthorizationCodeService;
import com.Authentication.AuthService.services.auth.FaceAuthService;
import com.Authentication.AuthService.services.auth.JwtService;
import com.Authentication.AuthService.services.auth.TokenService;
import com.Authentication.AuthService.services.user.UserService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Controller
@RequestMapping("/oauth2")
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthorizationController {

    private final RegisteredClientRepository registeredClientRepository;
    private final FaceAuthService faceAuthService;
    private final AuthorizationCodeService authorizationCodeService;
    private final TokenService tokenService;
    private final JwtService jwtService;
    private final UserService userService;
    private final UserRepository userRepository;

    @GetMapping("/authorize")
    public String authorize(
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "scope", defaultValue = "openid profile") String scope,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "nonce", required = false) String nonce,
            @RequestParam(value = "code_challenge", required = false) String codeChallenge,
            @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod,
            @RequestParam(value = "response_type", defaultValue = "code") String responseType,
            Model model,
            HttpServletResponse response) throws IOException {

        log.info("Nhận yêu cầu authorize - client_id: {}, redirect_uri: {}", clientId, redirectUri);

        // 1. Validate response_type
        if (!"code".equals(responseType)) {
            log.error("Response type không được hỗ trợ: {}", responseType);
            return redirectError(response, redirectUri, "unsupported_response_type",
                    "Chỉ hỗ trợ response_type=code", state);
        }

        // 2. Tìm RegisteredClient
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            log.error("Client không tồn tại: {}", clientId);
            return redirectError(response, redirectUri, "invalid_client",
                    "Client ID không hợp lệ", state);
        }

        // 3. Validate redirect_uri
        if (!registeredClient.getRedirectUris().contains(redirectUri)) {
            log.error("Redirect URI không hợp lệ: {}. Registered URIs: {}",
                    redirectUri, registeredClient.getRedirectUris());
            model.addAttribute("error", "invalid_redirect_uri");
            model.addAttribute("error_description", "Redirect URI không được đăng ký");
            return "error";
        }

        // 4. Validate scope
        String[] requestedScopes = scope.split(" ");
        for (String requestedScope : requestedScopes) {
            if (!registeredClient.getScopes().contains(requestedScope)) {
                log.error("Scope không hợp lệ: {}", requestedScope);
                return redirectError(response, redirectUri, "invalid_scope",
                        "Scope '" + requestedScope + "' không được phép", state);
            }
        }

        // 5. Validate các tham số PKCE nếu có
        if (StringUtils.hasText(codeChallenge) && !StringUtils.hasText(codeChallengeMethod)) {
            codeChallengeMethod = "plain";
        }

        if (!StringUtils.hasText(codeChallenge) && StringUtils.hasText(codeChallengeMethod)) {
            log.error("Thiếu code_challenge khi client gửi code_challenge_method");
            return redirectError(response, redirectUri, "invalid_request",
                    "code_challenge là bắt buộc khi client gửi code_challenge_method", state);
        }

        if (StringUtils.hasText(codeChallengeMethod) && !isSupportedCodeChallengeMethod(codeChallengeMethod)) {
            log.error("code_challenge_method không được hỗ trợ: {}", codeChallengeMethod);
            return redirectError(response, redirectUri, "invalid_request",
                    "code_challenge_method chỉ hỗ trợ plain hoặc S256", state);
        }

        // 6. Lưu thông tin vào model
        model.addAttribute("client_id", clientId);
        model.addAttribute("redirect_uri", redirectUri);
        model.addAttribute("scope", scope);
        model.addAttribute("state", state != null ? state : "");
        model.addAttribute("nonce", nonce != null ? nonce : "");
        model.addAttribute("code_challenge", codeChallenge != null ? codeChallenge : "");
        model.addAttribute("code_challenge_method", codeChallengeMethod != null ? codeChallengeMethod : "");
        model.addAttribute("client_name", registeredClient.getClientName());

        log.info("Hiển thị form Face Authentication cho client: {}", registeredClient.getClientName());

        return "face-login";
    }

    @PostMapping("/face-auth/login")
    public void faceAuthLogin(
            @ModelAttribute FaceAuthLoginRequestDto request,
            HttpServletResponse response) throws IOException {

        log.info("Nhận yêu cầu face-auth login - username: {}, client_id: {}",
                request.getUsername(), request.getClientId());

        try {
            // 1. Validate client_id
            RegisteredClient registeredClient = registeredClientRepository.findByClientId(request.getClientId());
            if (registeredClient == null) {
                log.error("Client không tồn tại: {}", request.getClientId());
                redirectWithError(response, request.getRedirectUri(), "invalid_client",
                        "Client không hợp lệ", request.getState());
                return;
            }

            // 2. Validate redirect_uri
            if (!registeredClient.getRedirectUris().contains(request.getRedirectUri())) {
                log.error("Redirect URI không hợp lệ: {}", request.getRedirectUri());
                redirectWithError(response, request.getRedirectUri(), "invalid_redirect_uri",
                        "Redirect URI không hợp lệ", request.getState());
                return;
            }

            // 3. Gọi Server A để verify face
            // log.info("Đang gọi Server A để xác thực khuôn mặt cho user: {}", request.getUsername());

            // Optional<User> faceDataOpt = userRepository.findByUsername(request.getUsername());

            // if (!faceDataOpt.isPresent()) {
            //     log.error("Không tìm thấy dữ liệu khuôn mặt cho user: {}", request.getUsername());
            //     redirectWithError(response, request.getRedirectUri(), "access_denied",
            //             "Người dùng chưa đăng ký khuôn mặt", request.getState());
            //     return;
            // }

            // User faceData = faceDataOpt.get();

            // // Gọi đúng method verifyUser với đầy đủ tham số
            // boolean verifySuccess = faceAuthService.verifyUser(
            //         request.getUsername(),
            //         faceData.getHelperData(), // helper_data_b64
            //         faceData.getKeyHash() // key_hash_b64
            // );

            // if (!verifySuccess) {
            //     log.warn("Xác thực khuôn mặt thất bại cho user: {}", request.getUsername());
            //     redirectWithError(response, request.getRedirectUri(), "access_denied",
            //             "Xác thực khuôn mặt thất bại", request.getState());
            //     return;
            // }

            // log.info("Xác thực khuôn mặt thành công cho user: {}", request.getUsername());

            // Chuẩn hóa các tham số tuỳ chọn trước khi lưu
            String sanitizedNonce = StringUtils.hasText(request.getNonce()) ? request.getNonce() : null;
            String sanitizedCodeChallenge = StringUtils.hasText(request.getCodeChallenge()) ? request.getCodeChallenge()
                    : null;
            String sanitizedCodeChallengeMethod = StringUtils.hasText(request.getCodeChallengeMethod())
                    ? request.getCodeChallengeMethod()
                    : null;

            // 4. Tạo authorization_code
            String authorizationCode = authorizationCodeService.generateAuthorizationCode(
                    request.getClientId(),
                    request.getUsername(),
                    request.getRedirectUri(),
                    request.getScope(),
                    request.getState(),
                    sanitizedNonce,
                    sanitizedCodeChallenge,
                    sanitizedCodeChallengeMethod);

            log.info("Đã tạo authorization_code: {} cho user: {}", authorizationCode, request.getUsername());

            // 5. Redirect về Client với code
            String redirectUrl = buildSuccessRedirectUrl(
                    request.getRedirectUri(),
                    authorizationCode,
                    request.getState());

            log.info("Redirect về Client: {}", redirectUrl);
            response.sendRedirect(redirectUrl);

        } catch (Exception e) {
            log.error("Lỗi trong quá trình face authentication: ", e);
            redirectWithError(response, request.getRedirectUri(), "server_error",
                    "Lỗi server khi xác thực", request.getState());
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

    private String buildSuccessRedirectUrl(String redirectUri, String code, String state) {
        StringBuilder url = new StringBuilder(redirectUri);
        url.append(redirectUri.contains("?") ? "&" : "?");
        url.append("code=").append(URLEncoder.encode(code, StandardCharsets.UTF_8));

        if (state != null && !state.isEmpty()) {
            url.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8));
        }

        return url.toString();
    }

    private boolean isSupportedCodeChallengeMethod(String method) {
        return "plain".equalsIgnoreCase(method) || "S256".equalsIgnoreCase(method);
    }

    private void redirectWithError(HttpServletResponse response, String redirectUri,
            String error, String errorDescription, String state) throws IOException {
        String errorUrl = buildErrorRedirectUrl(redirectUri, error, errorDescription, state);
        response.sendRedirect(errorUrl);
    }

    private String buildErrorRedirectUrl(String redirectUri, String error,
            String errorDescription, String state) {
        StringBuilder url = new StringBuilder(redirectUri);
        url.append(redirectUri.contains("?") ? "&" : "?");
        url.append("error=").append(URLEncoder.encode(error, StandardCharsets.UTF_8));
        url.append("&error_description=").append(URLEncoder.encode(errorDescription, StandardCharsets.UTF_8));

        if (state != null && !state.isEmpty()) {
            url.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8));
        }

        return url.toString();
    }

    private String redirectError(HttpServletResponse response, String redirectUri,
            String error, String errorDescription, String state) throws IOException {
        if (redirectUri != null && !redirectUri.isEmpty()) {
            redirectWithError(response, redirectUri, error, errorDescription, state);
            return null;
        } else {
            return "redirect:/error?error=" + error + "&error_description=" + errorDescription;
        }
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