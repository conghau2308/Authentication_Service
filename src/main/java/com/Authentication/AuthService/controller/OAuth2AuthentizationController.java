package com.Authentication.AuthService.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import com.Authentication.AuthService.annotation.RateLimit;
import com.Authentication.AuthService.config.CookieConfig;
import com.Authentication.AuthService.dto.OAuth2ValidateClientResponseDto;
import com.Authentication.AuthService.dto.RefreshTokenResponseDto;
import com.Authentication.AuthService.dto.TokenResponseDto;
import com.Authentication.AuthService.dto.oauth.AuthorizeRequestDto;
import com.Authentication.AuthService.dto.oauth.AuthorizeResponseDto;
import com.Authentication.AuthService.dto.oauth.ConsentRequestDto;
import com.Authentication.AuthService.dto.oauth.IntrospectionResponseDto;
import com.Authentication.AuthService.dto.oauth.UserInforResponseDto;
import com.Authentication.AuthService.dto.response.ApiResponse;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.enums.LimitStrategy;
import com.Authentication.AuthService.exception.business.BusinessException;
import com.Authentication.AuthService.services.oauth.AccessTokenService;
import com.Authentication.AuthService.services.oauth.AuthenticationService;
import com.Authentication.AuthService.services.oauth.UserInforService;

import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/oauth2")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "OAuth Authentization", description = "APIs for OAuth authentication and authorization")
@RateLimit(limit = 1000, durationSeconds = 60, strategy = LimitStrategy.BY_CLIENT_ID)
public class OAuth2AuthentizationController {

    private final AuthenticationService authenticationService;
    private final UserInforService userInforService;
    private final AccessTokenService accessTokenService;
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

    @RateLimit(limit = 50, durationSeconds = 60, strategy = LimitStrategy.BY_USER)
    @PostMapping("/authorize")
    public ResponseEntity<ApiResponse<AuthorizeResponseDto>> authorize(
            @RequestBody AuthorizeRequestDto request,
            @AuthenticationPrincipal User user) {
        AuthorizeResponseDto result = authenticationService.authorize(request, user);
        return ResponseEntity.ok(ApiResponse.success(result, "Authorize thành công."));
    }

    @RateLimit(limit = 50, durationSeconds = 60, strategy = LimitStrategy.BY_USER)
    @PostMapping("/authorize/consent")
    public ResponseEntity<ApiResponse<AuthorizeResponseDto>> confirmConsent(
            @RequestBody ConsentRequestDto request,
            @AuthenticationPrincipal User user) {
        AuthorizeResponseDto result = authenticationService.confirmConsent(request, user);
        return ResponseEntity.ok(ApiResponse.success(result, "Xác nhận consent thành công."));
    }

    /**
     * Endpoint /token — xử lý authorization_code và refresh_token (RFC 6749).
     * Client authentication qua HTTP Basic Auth (RFC 6749 §2.3.1):
     *   Authorization: Basic base64(client_id:client_secret)
     */
    @PostMapping("/token")
    public ResponseEntity<?> token(
            @RequestHeader("Authorization") String authHeader,
            @RequestParam("grant_type") String grantType,
            @RequestParam(required = false) String code,
            @RequestParam(value = "code_verifier", required = false) String codeVerifier,
            @RequestParam(required = false) String state,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "refresh_token", required = false) String refreshToken) {

        String[] creds = parseBasicAuth(authHeader);
        String clientId = creds[0];
        String clientSecret = creds[1];

        if ("authorization_code".equals(grantType)) {
            TokenResponseDto result = authenticationService.exchangeTokens(
                    grantType, clientId, clientSecret, code, codeVerifier, state, redirectUri);
            return ResponseEntity.ok(result);
        } else if ("refresh_token".equals(grantType)) {
            RefreshTokenResponseDto result = authenticationService.refreshToken(
                    grantType, clientId, clientSecret, refreshToken);
            return ResponseEntity.ok(result);
        }
        throw new BusinessException("UNSUPPORTED_GRANT_TYPE",
                "Chỉ hỗ trợ grant_type=authorization_code hoặc refresh_token.");
    }

    /**
     * Endpoint /refresh — giữ lại để backward compat.
     * Client authentication qua HTTP Basic Auth (RFC 6749 §2.3.1).
     */
    @PostMapping("/refresh")
    public ResponseEntity<RefreshTokenResponseDto> refresh(
            @RequestHeader("Authorization") String authHeader,
            @RequestParam("grant_type") String grantType,
            @RequestParam("refresh_token") String refreshToken) {
        String[] creds = parseBasicAuth(authHeader);
        RefreshTokenResponseDto result = authenticationService.refreshToken(
                grantType, creds[0], creds[1], refreshToken);
        return ResponseEntity.ok(result);
    }

    /**
     * RFC 7662 Token Introspection — resource server gọi để kiểm tra opaque access token.
     * Client authentication qua HTTP Basic Auth (RFC 6749 §2.3.1).
     * Trả về active=false thay vì lỗi khi token không hợp lệ.
     */
    @PostMapping("/introspect")
    public ResponseEntity<IntrospectionResponseDto> introspect(
            @RequestHeader("Authorization") String authHeader,
            @RequestParam("token") String token) {
        String[] creds = parseBasicAuth(authHeader);
        authenticationService.validateClientCredentials(creds[0], creds[1]);
        IntrospectionResponseDto result = accessTokenService.introspect(token);
        return ResponseEntity.ok(result);
    }

    /**
     * Endpoint để revoke refresh token.
     * Client authentication qua HTTP Basic Auth (RFC 6749 §2.3.1).
     */
    @PostMapping("/revoke")
    public ResponseEntity<ApiResponse<Void>> revokeToken(
            @RequestHeader("Authorization") String authHeader,
            @RequestParam("token") String token,
            @RequestParam("token_type_hint") String tokenTypeHint) {

        String[] creds = parseBasicAuth(authHeader);
        authenticationService.revoke(token, tokenTypeHint, creds[0], creds[1]);

        return ResponseEntity.ok(ApiResponse.<Void>success(null, "Revoke token thành công."));
    }

    /** Parse HTTP Basic Auth header → [clientId, clientSecret] (RFC 6749 §2.3.1). */
    private String[] parseBasicAuth(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Basic ")) {
            throw new BusinessException("INVALID_CLIENT",
                    "Client authentication yêu cầu Authorization: Basic base64(client_id:client_secret).");
        }
        try {
            String decoded = new String(java.util.Base64.getDecoder().decode(authHeader.substring(6)));
            int colon = decoded.indexOf(':');
            if (colon < 1) {
                throw new BusinessException("INVALID_CLIENT", "Basic Auth credentials không hợp lệ.");
            }
            return new String[]{ decoded.substring(0, colon), decoded.substring(colon + 1) };
        } catch (IllegalArgumentException e) {
            throw new BusinessException("INVALID_CLIENT", "Base64 encoding trong Authorization header không hợp lệ.");
        }
    }

    /**
     * OIDC UserInfo Endpoint
     * GET /oauth2/userinfo
     * Header: Authorization: Bearer {access_token}
     */
    // Chú ý: hiện tại code đang filter header thủ công nên hãy xem cách sử dụng
    // java security nếu cần thiết
    @RateLimit(limit = 50, durationSeconds = 60, strategy = LimitStrategy.BY_USER)
    @GetMapping("/userinfo")
    public ResponseEntity<UserInforResponseDto> getUserInfo(
            @RequestHeader("Authorization") String authorization) {
        UserInforResponseDto result = userInforService.getUserInfo(authorization);

        return ResponseEntity.ok(result);
    }
}