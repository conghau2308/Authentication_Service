package com.Authentication.AuthService.controller;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.Authentication.AuthService.dto.FaceAuthLoginRequestDto;
import com.Authentication.AuthService.services.auth.AuthorizationCodeService;
import com.Authentication.AuthService.services.auth.FaceAuthService;

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

    @GetMapping("/authorize")
    public String authorize(
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "scope", defaultValue = "openid profile") String scope,
            @RequestParam(value = "state", required = false) String state,
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

        // 5. Lưu thông tin vào model
        model.addAttribute("client_id", clientId);
        model.addAttribute("redirect_uri", redirectUri);
        model.addAttribute("scope", scope);
        model.addAttribute("state", state != null ? state : "");
        model.addAttribute("client_name", registeredClient.getClientName());

        log.info("Hiển thị form Face Authentication cho client: {}", registeredClient.getClientName());
        
        // ✅ THÊM PREFIX THYMELEAF
        return "face-login";  // Thymeleaf sẽ tự tìm templates/face-login.html
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
            log.info("Đang gọi Server A để xác thực khuôn mặt cho user: {}", request.getUsername());
            boolean verifySuccess = faceAuthService.verifyUser(request.getUsername());

            if (!verifySuccess) {
                log.warn("Xác thực khuôn mặt thất bại cho user: {}", request.getUsername());
                redirectWithError(response, request.getRedirectUri(), "access_denied",
                        "Xác thực khuôn mặt thất bại", request.getState());
                return;
            }

            log.info("Xác thực khuôn mặt thành công cho user: {}", request.getUsername());

            // 4. Tạo authorization_code
            String authorizationCode = authorizationCodeService.generateAuthorizationCode(
                    request.getClientId(),
                    request.getUsername(),
                    request.getRedirectUri(),
                    request.getScope());

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
}