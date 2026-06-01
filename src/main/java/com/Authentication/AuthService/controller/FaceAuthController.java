package com.Authentication.AuthService.controller;

import java.util.Arrays;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.Authentication.AuthService.annotation.RateLimit;
import com.Authentication.AuthService.config.CookieConfig;
import com.Authentication.AuthService.dto.CheckEmailRequestDto;
import com.Authentication.AuthService.dto.CheckUsernameRequestDto;
import com.Authentication.AuthService.dto.DeltaResponseDto;
import com.Authentication.AuthService.dto.UserEnrollRequestDto;
import com.Authentication.AuthService.dto.UserVerifyRequestDto;
import com.Authentication.AuthService.dto.response.ApiResponse;
import com.Authentication.AuthService.dto.user.UserInforResponseDto;
import com.Authentication.AuthService.dto.user.UsernameAvailabilityDto;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.services.enrollment.UserEnrollService;

import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/auth")
@Slf4j
@RequiredArgsConstructor
@Tag(name = "Face auth", description = "Apis for managing users and authenticate")
public class FaceAuthController {
        private final UserEnrollService userEnrollService;
        private final CookieConfig cookieConfig;

        @SecurityRequirements
        @PostMapping("/enroll")
        public ResponseEntity<ApiResponse<Void>> registerNewUser(@Valid @RequestBody UserEnrollRequestDto request) {
                userEnrollService.enroll(request);

                return ResponseEntity.status(HttpStatus.CREATED).body(
                                ApiResponse.success(null, "Đăng ký tài khoản thành công."));
        }

        @RateLimit(limit = 100, durationSeconds = 60)
        @SecurityRequirements
        @PostMapping("/check-username")
        public ResponseEntity<ApiResponse<UsernameAvailabilityDto>> checkUsernameAvailability(
                        @Valid @RequestBody CheckUsernameRequestDto request) {
                UsernameAvailabilityDto response = userEnrollService.checkUsernameAvailability(request.getUsername());
                String message = response.isAvailable() ? "Username có thể sử dụng." : "Username đã được sử dụng.";
                return ResponseEntity.ok(ApiResponse.success(response, message));
        }

        @RateLimit(limit = 100, durationSeconds = 60)
        @SecurityRequirements
        @PostMapping("/check-email")
        public ResponseEntity<ApiResponse<UsernameAvailabilityDto>> checkEmailAvailability(
                        @Valid @RequestBody CheckEmailRequestDto request) {
                UsernameAvailabilityDto response = userEnrollService.checkEmailAvailability(request.getEmail());
                String message = response.isAvailable() ? "Email có thể sử dụng." : "Email đã được sử dụng.";
                return ResponseEntity.ok(ApiResponse.success(response, message));
        }

        @SecurityRequirements
        @PostMapping("/verify")
        public ResponseEntity<ApiResponse<String>> verifyUser(
                        @Valid @RequestBody UserVerifyRequestDto request,
                        HttpServletResponse response) {
                String token = userEnrollService.verify(request, response);

                return ResponseEntity.ok(ApiResponse.success(token, "Xác thực thành công."));
        }

        @SecurityRequirements
        @PostMapping("/refresh")
        public ResponseEntity<ApiResponse<Void>> refreshToken(
                        HttpServletRequest request,
                        HttpServletResponse response) {
                String refreshToken = extractRefreshTokenFromCookie(request);
                userEnrollService.refresh(refreshToken, response);

                return ResponseEntity.ok(ApiResponse.success(null, "Refresh token thành công."));
        }

        @SecurityRequirements
        @PostMapping("/logout")
        public ResponseEntity<ApiResponse<Void>> logout(
                        HttpServletRequest request,
                        HttpServletResponse response) {
                // Đã clear tất cả cookies
                // Lấy refresh token để kiểm tra xem có tokens không nếu có thì mới logout
                // còn không thì không cho logout nữa
                String refreshToken = extractRefreshTokenFromCookie(request);
                userEnrollService.logout(refreshToken, response);

                return ResponseEntity.ok(ApiResponse.success(null, "Đăng xuất thành công."));
        }

        /**
         * Trả về helper_data (δ) và mask cho client để chạy WiFaKey verify cục bộ.
         * Yêu cầu state từ OAuth flow — buộc caller phải đang trong một phiên PKCE hợp lệ.
         * Không trả key_hash — client không cần và không nên biết.
         */
        @SecurityRequirements
        @RateLimit(limit = 5, durationSeconds = 60)
        @GetMapping("/delta")
        public ResponseEntity<ApiResponse<DeltaResponseDto>> getDelta(
                        @RequestParam String username,
                        @RequestParam String state) {
                if (state == null || state.isBlank() || state.length() < 16) {
                        throw new com.Authentication.AuthService.exception.business.BusinessException(
                                "INVALID_STATE", "state parameter không hợp lệ.");
                }
                DeltaResponseDto delta = userEnrollService.getDelta(username);
                return ResponseEntity.ok(ApiResponse.success(delta, "Lấy helper data thành công."));
        }

        @RateLimit(limit = 100, durationSeconds = 60)
        @GetMapping("/me")
        public ResponseEntity<ApiResponse<UserInforResponseDto>> getMe(@AuthenticationPrincipal User user) {
                UserInforResponseDto response = UserInforResponseDto.builder()
                                .userId(user.getId().toString())
                                .name(user.getName())
                                .email(user.getEmail())
                                .role(user.getRole())
                                .isActive(user.isActive())
                                .build();
                return ResponseEntity.ok(ApiResponse.success(response, "Lấy thông tin thành công."));
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