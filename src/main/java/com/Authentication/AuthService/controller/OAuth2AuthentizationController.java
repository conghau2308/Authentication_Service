package com.Authentication.AuthService.controller;

import java.util.Arrays;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import com.Authentication.AuthService.config.CookieConfig;
import com.Authentication.AuthService.dto.OAuth2ValidateClientResponseDto;
import com.Authentication.AuthService.dto.RefreshTokenResponseDto;
import com.Authentication.AuthService.dto.TokenResponseDto;
import com.Authentication.AuthService.dto.oauth.AuthorizeRequestDto;
import com.Authentication.AuthService.dto.oauth.AuthorizeResponseDto;
import com.Authentication.AuthService.dto.oauth.ConsentRequestDto;
import com.Authentication.AuthService.dto.oauth.UserInforResponseDto;
import com.Authentication.AuthService.dto.response.ApiResponse;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.services.oauth.AuthenticationService;
import com.Authentication.AuthService.services.oauth.UserInforService;

import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/oauth2")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "OAuth Authentization", description = "APIs for OAuth authentication and authorization")
public class OAuth2AuthentizationController {

    private final AuthenticationService authenticationService;
    private final UserInforService userInforService;
    private final CookieConfig cookieConfig;

    /**
     * API 1: Validate OAuth parameters
     * Frontend gọi API này khi page load để validate trước khi hiển thị UI
     */
    @GetMapping("/validate")
    public ResponseEntity<ApiResponse<OAuth2ValidateClientResponseDto>> validateAuthorization(
            @RequestParam(value = "client_id", required = true) String clientId,
            @RequestParam(value = "redirect_uri", required = true) String redirectUri,
            @RequestParam(value = "scope", required = true) String scope,
            @RequestParam(value = "response_type", required = true) String responseType,
            @RequestParam(value = "state", required = true) String state,
            @RequestParam(value = "nonce", required = true) String nonce,
            @RequestParam(value = "code_challenge", required = true) String codeChallenge,
            @RequestParam(value = "code_challenge_method", required = true) String codeChallengeMethod) {

        OAuth2ValidateClientResponseDto result = authenticationService.validateParams(clientId, redirectUri,
                scope, responseType, state, nonce, codeChallenge, codeChallengeMethod);

        return ResponseEntity.ok(ApiResponse.success(result, "Các tham số là hợp lệ."));
    }

    @PostMapping("/authorize")
    public ResponseEntity<ApiResponse<AuthorizeResponseDto>> authorize(
            @RequestBody AuthorizeRequestDto request,
            @AuthenticationPrincipal User user) {
        AuthorizeResponseDto result = authenticationService.authorize(request, user);
        return ResponseEntity.ok(ApiResponse.success(result, "Authorize thành công."));
    }

    @PostMapping("/authorize/consent")
    public ResponseEntity<ApiResponse<AuthorizeResponseDto>> confirmConsent(
            @RequestBody ConsentRequestDto request,
            @AuthenticationPrincipal User user) {
        AuthorizeResponseDto result = authenticationService.confirmConsent(request, user);
        return ResponseEntity.ok(ApiResponse.success(result, "Xác nhận consent thành công."));
    }

    /**
     * Endpoint /token xử lý cả authorization_code và refresh_token grant types
     */
    @PostMapping("/token")
    public ResponseEntity<ApiResponse<TokenResponseDto>> token(
            @RequestParam(value = "grant_type", required = true) String grantType,
            @RequestParam(value = "client_id", required = true) String clientId,
            @RequestParam(value = "client_secret", required = true) String clientSecret,
            @RequestParam(value = "code", required = true) String code,
            @RequestParam(value = "code_verifier", required = true) String codeVerifier,
            @RequestParam(value = "state", required = true) String state,
            @RequestParam(value = "redirect_uri", required = true) String redirectUri) {
        TokenResponseDto result = authenticationService.exchangeTokens(grantType, clientId, clientSecret, code,
                codeVerifier, state, redirectUri);

        return ResponseEntity.ok(ApiResponse.success(result, "Đổi tokens thành công."));
    }

    // Endpoint để Client refresh token của user
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<RefreshTokenResponseDto>> refresh(
            @RequestParam(value = "grant_type", required = true) String grantType,
            @RequestParam(value = "client_id", required = true) String clientId,
            @RequestParam(value = "client_secret", required = true) String clientSecret,
            @RequestParam(value = "refresh_code", required = true) String refreshToken) {
        RefreshTokenResponseDto result = authenticationService.refreshToken(grantType, clientId, clientSecret,
                refreshToken);

        return ResponseEntity.ok(ApiResponse.success(result, "Refresh thành công."));
    }

    /**
     * Endpoint để revoke refresh token
     */
    @PostMapping("/revoke")
    public ResponseEntity<ApiResponse<Void>> revokeToken(
            @RequestParam("token") String token,
            @RequestParam("token_type_hint") String tokenTypeHint,
            @RequestParam("client_id") String clientId,
            @RequestParam("client_secret") String clientSecret) {

        authenticationService.revoke(token, tokenTypeHint, clientId, clientSecret);

        return ResponseEntity.ok(ApiResponse.success(null, "Revoke token thành công."));
    }

    /**
     * OIDC UserInfo Endpoint
     * GET /oauth2/userinfo
     * Header: Authorization: Bearer {access_token}
     */
    // Chú ý: hiện tại code đang filter header thủ công nên hãy xem cách sử dụng
    // java security nếu cần thiết
    @GetMapping("/userinfo")
    public ResponseEntity<ApiResponse<UserInforResponseDto>> getUserInfo(
            @RequestHeader("Authorization") String authorization) {
        UserInforResponseDto result = userInforService.getUserInfo(authorization);

        return ResponseEntity.ok(ApiResponse.success(result, "Lấy thông tin user thành công."));
    }

    /**
     * OAuth Logout - Clear OAuth cookies only
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            HttpServletRequest request,
            HttpServletResponse response) {
        String refreshToken = extractRefreshTokenFromCookie(request);
        authenticationService.logout(refreshToken, response);

        return ResponseEntity.ok(ApiResponse.success(null, "Đăng xuất thành công."));
    }

    private String extractRefreshTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return null;
        }

        return Arrays.stream(request.getCookies())
                .filter(cookie -> cookieConfig.getRefreshTokenName().equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }
}