package com.Authentication.AuthService.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.Authentication.AuthService.dto.AuthenticateRequestDto;
import com.Authentication.AuthService.dto.OAuth2ValidateClientResponseDto;
import com.Authentication.AuthService.dto.RefreshTokenResponseDto;
import com.Authentication.AuthService.dto.TokenResponseDto;
import com.Authentication.AuthService.dto.OAuth.CheckSSORequestDto;
import com.Authentication.AuthService.dto.OAuth.FaceAuthRequestDto;
import com.Authentication.AuthService.dto.OAuth.SSOAuthorizeRequestDto;
import com.Authentication.AuthService.dto.OAuth.SSOStatusResponseDto;
import com.Authentication.AuthService.dto.OAuth.UserInforResponseDto;
import com.Authentication.AuthService.dto.OAuth.ValidateOAuthResponseDto;
import com.Authentication.AuthService.dto.Response.ApiResponse;
import com.Authentication.AuthService.services.oauth.OAuth2AuthenticationService;
import com.Authentication.AuthService.services.oauth.UserInforService;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/oauth2")
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthentizationController {

    private final OAuth2AuthenticationService oAuth2AuthenticationService;
    private final UserInforService userInforService;

    private static final String ACCESS_TOKEN_COOKIE = "ACCESS_TOKEN";
    private static final String REFRESH_TOKEN_COOKIE = "REFRESH_TOKEN";

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

        OAuth2ValidateClientResponseDto result = oAuth2AuthenticationService.validateParams(clientId, redirectUri,
                scope, responseType, state, nonce, codeChallenge, codeChallengeMethod);

        return ResponseEntity.ok(ApiResponse.success(result, "Các tham số là hợp lệ."));
    }

    /**
     * API 2: Authenticate user với face recognition
     * Frontend gọi API này sau khi user nhập username và chụp ảnh
     */
    // Cần chú ý xem có cần tạo redirect error&errorDescription cho client không
    @PostMapping("/authorize")
    public ResponseEntity<ApiResponse<ValidateOAuthResponseDto>> authenticate(
            @RequestBody AuthenticateRequestDto request,
            @CookieValue(name = ACCESS_TOKEN_COOKIE, required = false) String accessToken,
            HttpServletResponse httpResponse) {
        ValidateOAuthResponseDto result = oAuth2AuthenticationService.validateLogin(request, accessToken, httpResponse);

        return ResponseEntity.ok(ApiResponse.success(result, "Xác thực thành công."));
    }

    @PostMapping("/check-session")
    public ResponseEntity<ApiResponse<SSOStatusResponseDto>> checkSSOStatus(
            @RequestBody CheckSSORequestDto request,
            @CookieValue(name = ACCESS_TOKEN_COOKIE, required = false) String accessToken) {
        SSOStatusResponseDto result = oAuth2AuthenticationService.checkSSOStatus(request, accessToken);
        return ResponseEntity.ok(ApiResponse.success(result, "KIểm tra session thành công."));
    }

    @PostMapping("/authorize/face-auth")
    public ResponseEntity<ApiResponse<ValidateOAuthResponseDto>> authenticateWithFace(
            @RequestBody FaceAuthRequestDto request, HttpServletResponse response) {
        ValidateOAuthResponseDto result = oAuth2AuthenticationService.authenticateWithFace(request, response);
        return ResponseEntity.ok(ApiResponse.success(result, "Xác thực khuôn mtajw thành công."));
    }

    @PostMapping("authorize/sso")
    public ResponseEntity<ApiResponse<ValidateOAuthResponseDto>> authorizeWithSSO(
            @RequestBody SSOAuthorizeRequestDto request,
            @CookieValue(name = ACCESS_TOKEN_COOKIE, required = false) String accessToken,
            HttpServletResponse response) {
        ValidateOAuthResponseDto result = oAuth2AuthenticationService.authorizeWithSSO(request, accessToken, response);
        return ResponseEntity.ok(ApiResponse.success(result, "Xác thực SSO thành công."));
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
        TokenResponseDto result = oAuth2AuthenticationService.exchangeTokens(grantType, clientId, clientSecret, code,
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
        RefreshTokenResponseDto result = oAuth2AuthenticationService.refreshToken(grantType, clientId, clientSecret,
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

        oAuth2AuthenticationService.revoke(token, tokenTypeHint, clientId, clientSecret);

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
            @CookieValue(value = REFRESH_TOKEN_COOKIE, required = true) String refreshToken,
            HttpServletResponse response) {
        oAuth2AuthenticationService.logout(refreshToken, response);

        return ResponseEntity.ok(ApiResponse.success(null, "Đăng xuất thành công."));
    }
}