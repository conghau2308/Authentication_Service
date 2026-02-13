package com.Authentication.AuthService.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.Authentication.AuthService.dto.UserEnrollRequestDto;
import com.Authentication.AuthService.dto.UserVerifyRequestDto;
import com.Authentication.AuthService.dto.Response.ApiResponse;
import com.Authentication.AuthService.dto.user.UsernameAvailabilityDto;
import com.Authentication.AuthService.services.enrollment.UserEnrollService;

import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("auth")
@Slf4j
@RequiredArgsConstructor
@Tag(name = "Face auth", description = "Apis for managing users and authenticate")
public class FaceAuthController {
        private final UserEnrollService userEnrollService;

        // Chú ý nhất quán về tên refresh token
        private static final String REFRESH_TOKEN_COOKIE = "REFRESH_TOKEN";

        @PostMapping("/enroll")
        public ResponseEntity<ApiResponse<Void>> registerNewUser(@Valid @RequestBody UserEnrollRequestDto request) {
                userEnrollService.enroll(request);

                return ResponseEntity.status(HttpStatus.CREATED).body(
                                ApiResponse.success(null, "Đăng ký tài khoản thành công."));
        }

        @PostMapping("/check-username")
        public ResponseEntity<ApiResponse<UsernameAvailabilityDto>> checkUsernameAvailability(
                        @RequestBody String username) {
                UsernameAvailabilityDto response = userEnrollService.checkUsernameAvailability(username);

                return ResponseEntity.ok(ApiResponse.success(response, "Kiểm tra username thành công."));
        }

        @PostMapping("/verify")
        public ResponseEntity<ApiResponse<Void>> verifyUser(
                        @Valid @RequestBody UserVerifyRequestDto request,
                        HttpServletResponse response) {
                userEnrollService.verify(request, response);

                return ResponseEntity.ok(ApiResponse.success(null, "Xác thực thành công."));
        }

        @PostMapping("/refresh")
        public ResponseEntity<ApiResponse<Void>> refreshToken(
                        @CookieValue(name = REFRESH_TOKEN_COOKIE, required = false) String refreshToken,
                        HttpServletResponse response) {
                userEnrollService.refresh(refreshToken, response);

                return ResponseEntity.ok(ApiResponse.success(null, "Refresh token thành công."));
        }

        @PostMapping("/logout")
        public ResponseEntity<ApiResponse<Void>> logout(
                        @CookieValue(name = REFRESH_TOKEN_COOKIE, required = true) String refreshToken,
                        HttpServletResponse response) {
                // Đã clear tất cả cookies
                // Lấy refresh token để kiểm tra xem có tokens không nếu có thì mới logput
                // còn không thì không cho logput nữa
                userEnrollService.logout(refreshToken, response);

                return ResponseEntity.ok(ApiResponse.success(null, "Đăng xuất thành công."));
        }
}