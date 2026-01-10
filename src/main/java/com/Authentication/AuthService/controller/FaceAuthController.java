package com.Authentication.AuthService.controller;

import com.Authentication.AuthService.dto.*;
import com.Authentication.AuthService.entity.AuthRefreshToken;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.repository.AuthRefreshTokenRepository;
import com.Authentication.AuthService.repository.UserRepository;
import com.Authentication.AuthService.services.auth.AuthJwtService;
import com.Authentication.AuthService.services.auth.FaceAuthService;
import com.Authentication.AuthService.services.auth.FaceAuthService.PythonApiException;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Optional;

@RestController
@RequestMapping("/face-auth")
@Slf4j
@RequiredArgsConstructor
public class FaceAuthController {
        private final FaceAuthService faceAuthService;
        private final UserRepository userRepository;
        private final AuthJwtService authJwtService;
        private final AuthRefreshTokenRepository authRefreshTokenRepository;

        private static final String REFRESH_TOKEN_COOKIE = "refresh_token";
        private static final int REFRESH_TOKEN_MAX_AGE = 1 * 24 * 60 * 60; // 1 day (24 Hours) in seconds

        private static final String ACCESS_TOKEN_COOKIE = "access_token";
        private static final int ACCESS_TOKEN_MAX_AGE = 15 * 60; // 15 minutes

        /**
         * Endpoint đăng ký khuôn mặt
         */
        @PostMapping("/enroll")
        public ResponseEntity<ApiResponseDto> enrollFace(@Valid @RequestBody EnrollRequestDto request) {
                log.info("📝 Nhận yêu cầu đăng ký khuôn mặt cho user: {} (name: {}, email: {})",
                                request.getUsername(), request.getName(), request.getEmail());

                try {
                        if (userRepository.existsByUsername(request.getUsername())) {
                                return ResponseEntity.badRequest().body(ApiResponseDto.builder()
                                                .success(false)
                                                .message("Username đã được sử dụng")
                                                .errorCode("USERNAME_EXISTS")
                                                .build());
                        }

                        if (userRepository.existsByEmail(request.getEmail())) {
                                return ResponseEntity.badRequest().body(ApiResponseDto.builder()
                                                .success(false)
                                                .message("Email đã được sử dụng")
                                                .errorCode("EMAIL_EXISTS")
                                                .build());
                        }

                        if (request.getImage_b64() == null || request.getImage_b64().isEmpty()) {
                                return ResponseEntity.badRequest().body(ApiResponseDto.builder()
                                                .success(false)
                                                .message("Vui lòng gửi ảnh khuôn mặt")
                                                .errorCode("IMAGE_REQUIRED")
                                                .build());
                        }

                        EnrollResponseDto enrollResponse = faceAuthService.enrollUser(
                                        request.getUsername(),
                                        request.getImage_b64());

                        if (enrollResponse != null) {
                                User user = User.builder()
                                                .username(request.getUsername())
                                                .name(request.getName())
                                                .email(request.getEmail())
                                                .helperData(enrollResponse.getHelper_data_b64())
                                                .keyHash(enrollResponse.getKey_hash_b64())
                                                .build();

                                userRepository.save(user);

                                log.info("✅ Đăng ký khuôn mặt thành công và đã lưu DB cho user: {}",
                                                request.getUsername());

                                return ResponseEntity.ok(ApiResponseDto.builder()
                                                .success(true)
                                                .message("Đăng ký khuôn mặt thành công")
                                                .build());
                        } else {
                                return ResponseEntity.badRequest().body(ApiResponseDto.builder()
                                                .success(false)
                                                .message("Đăng ký khuôn mặt thất bại. Vui lòng thử lại.")
                                                .errorCode("ENROLL_FAILED")
                                                .build());
                        }

                } catch (PythonApiException e) {
                        log.error("❌ Python API error: {} (code: {})", e.getMessage(), e.getErrorCode());
                        HttpStatus httpStatus = mapPythonStatusCode(e.getStatusCode());

                        return ResponseEntity.status(httpStatus).body(ApiResponseDto.builder()
                                        .success(false)
                                        .message(e.getMessage())
                                        .errorCode(e.getErrorCode())
                                        .build());

                } catch (Exception e) {
                        log.error("❌ Lỗi không xác định khi đăng ký khuôn mặt: {}", e.getMessage(), e);
                        return ResponseEntity.internalServerError().body(ApiResponseDto.builder()
                                        .success(false)
                                        .message("Lỗi hệ thống: " + e.getMessage())
                                        .errorCode("SYSTEM_ERROR")
                                        .build());
                }
        }

        /**
         * Endpoint verify khuôn mặt - Trả về Access Token và Refresh Token
         */
        @PostMapping("/verify/{username}")
        public ResponseEntity<AuthResponseDto> verifyFace(
                        @PathVariable String username,
                        @Valid @RequestBody VerifyRequestDto request,
                        HttpServletResponse response) {

                log.info("🔍 Nhận yêu cầu xác thực khuôn mặt cho user: {}", username);

                try {
                        Optional<User> userOpt = userRepository.findByUsername(username);
                        if (userOpt.isEmpty()) {
                                return ResponseEntity.badRequest().body(AuthResponseDto.builder()
                                                .success(false)
                                                .message("User chưa đăng ký khuôn mặt")
                                                .build());
                        }

                        if (request.getImageBase64() == null || request.getImageBase64().isEmpty()) {
                                return ResponseEntity.badRequest().body(AuthResponseDto.builder()
                                                .success(false)
                                                .message("Vui lòng gửi ảnh khuôn mặt")
                                                .build());
                        }

                        User user = userOpt.get();

                        boolean verified = faceAuthService.verifyUser(
                                        username,
                                        request.getImageBase64(),
                                        user.getHelperData(),
                                        user.getKeyHash());

                        if (verified) {
                                // Update last verified time
                                user.setLastVerifiedAt(LocalDateTime.now());
                                userRepository.save(user);

                                // Generate Access Token
                                String accessToken = authJwtService.generateAccessToken(
                                                user.getUsername(),
                                                user.getEmail(),
                                                user.getName());

                                // Generate Refresh Token
                                String refreshToken = authJwtService.generateRefreshToken(user.getUsername());

                                // Revoke old refresh tokens
                                authRefreshTokenRepository.revokeAllByUsername(username, LocalDateTime.now());

                                // Save new refresh token to database
                                AuthRefreshToken refreshTokenEntity = AuthRefreshToken.builder()
                                                .token(refreshToken)
                                                .username(username)
                                                .expiresAt(LocalDateTime.now().plusDays(1))
                                                .build();
                                authRefreshTokenRepository.save(refreshTokenEntity);

                                // Set Refresh Token as HTTP-Only Cookie
                                setSecureCookie(response, REFRESH_TOKEN_COOKIE, refreshToken, REFRESH_TOKEN_MAX_AGE);

                                setSecureCookie(response, ACCESS_TOKEN_COOKIE, accessToken, ACCESS_TOKEN_MAX_AGE);

                                log.info("✅ Xác thực thành công và tạo tokens cho user: {}", username);

                                return ResponseEntity.ok(AuthResponseDto.builder()
                                                .success(true)
                                                .message("Xác thực khuôn mặt thành công")
                                                // Nếu sau này cần giải payload để lấy thông tin cơ bản thì có thể
                                                // uncomment
                                                // .accessToken(accessToken)
                                                // .tokenType("Bearer")
                                                // .expiresIn(15 * 60L) // 15 minutes
                                                .user(AuthResponseDto.UserInfoDto.builder()
                                                                .username(user.getUsername())
                                                                .name(user.getName())
                                                                .email(user.getEmail())
                                                                .build())
                                                .build());
                        } else {
                                return ResponseEntity.ok(AuthResponseDto.builder()
                                                .success(false)
                                                .message("Khuôn mặt không khớp. Vui lòng thử lại.")
                                                .build());
                        }

                } catch (PythonApiException e) {
                        log.error("❌ Python API verify error: {} (code: {})", e.getMessage(), e.getErrorCode());
                        HttpStatus httpStatus = mapPythonStatusCode(e.getStatusCode());

                        return ResponseEntity.status(httpStatus).body(AuthResponseDto.builder()
                                        .success(false)
                                        .message(e.getMessage())
                                        .build());

                } catch (Exception e) {
                        log.error("❌ Lỗi không xác định khi xác thực khuôn mặt: {}", e.getMessage(), e);
                        return ResponseEntity.internalServerError().body(AuthResponseDto.builder()
                                        .success(false)
                                        .message("Lỗi hệ thống: " + e.getMessage())
                                        .build());
                }
        }

        /**
         * Endpoint refresh access token
         */
        @PostMapping("/refresh")
        public ResponseEntity<AuthResponseDto> refreshToken(
                        @CookieValue(name = REFRESH_TOKEN_COOKIE, required = false) String refreshToken,
                        HttpServletResponse response) {

                log.info("🔄 Nhận yêu cầu refresh token");

                try {
                        if (refreshToken == null || refreshToken.isEmpty()) {
                                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(AuthResponseDto.builder()
                                                .success(false)
                                                .message("Refresh token không tồn tại")
                                                .build());
                        }

                        // Validate refresh token
                        if (!authJwtService.validateRefreshToken(refreshToken)) {
                                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(AuthResponseDto.builder()
                                                .success(false)
                                                .message("Refresh token không hợp lệ hoặc đã hết hạn")
                                                .build());
                        }

                        // Check if refresh token exists and not revoked
                        Optional<AuthRefreshToken> tokenOpt = authRefreshTokenRepository.findByToken(refreshToken);
                        if (tokenOpt.isEmpty() || tokenOpt.get().isRevoked() || tokenOpt.get().isExpired()) {
                                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(AuthResponseDto.builder()
                                                .success(false)
                                                .message("Refresh token không hợp lệ hoặc đã bị thu hồi")
                                                .build());
                        }

                        String username = authJwtService.extractUsername(refreshToken);
                        Optional<User> userOpt = userRepository.findByUsername(username);

                        if (userOpt.isEmpty()) {
                                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(AuthResponseDto.builder()
                                                .success(false)
                                                .message("User không tồn tại")
                                                .build());
                        }

                        User user = userOpt.get();

                        // Generate new Access Token
                        String newAccessToken = authJwtService.generateAccessToken(
                                        user.getUsername(),
                                        user.getEmail(),
                                        user.getName());

                        setSecureCookie(response, ACCESS_TOKEN_COOKIE, newAccessToken, ACCESS_TOKEN_MAX_AGE);

                        // Optional: Rotate refresh token (generate new one)
                        // String newRefreshToken =
                        // authJwtService.generateRefreshToken(user.getUsername());

                        // Revoke old refresh token
                        // AuthRefreshToken oldToken = tokenOpt.get();
                        // oldToken.setRevokedAt(LocalDateTime.now());
                        // authRefreshTokenRepository.save(oldToken);

                        // Save new refresh token
                        // AuthRefreshToken newRefreshTokenEntity = AuthRefreshToken.builder()
                        // .token(newRefreshToken)
                        // .username(username)
                        // .expiresAt(LocalDateTime.now().plusDays(7))
                        // .build();
                        // authRefreshTokenRepository.save(newRefreshTokenEntity);

                        // Update cookie with new refresh token
                        // Cookie newRefreshTokenCookie = new Cookie(REFRESH_TOKEN_COOKIE,
                        // newRefreshToken);
                        // newRefreshTokenCookie.setHttpOnly(true);
                        // newRefreshTokenCookie.setSecure(true);
                        // newRefreshTokenCookie.setPath("/");
                        // newRefreshTokenCookie.setMaxAge(REFRESH_TOKEN_MAX_AGE);
                        // newRefreshTokenCookie.setAttribute("SameSite", "Strict");
                        // response.addCookie(newRefreshTokenCookie);

                        log.info("✅ Refresh token thành công cho user: {}", username);

                        return ResponseEntity.ok(AuthResponseDto.builder()
                                        .success(true)
                                        .message("Refresh token thành công")
                                        // .accessToken(newAccessToken)
                                        // .tokenType("Bearer")
                                        // .expiresIn(15 * 60L)
                                        .user(AuthResponseDto.UserInfoDto.builder()
                                                        .username(user.getUsername())
                                                        .name(user.getName())
                                                        .email(user.getEmail())
                                                        .build())
                                        .build());

                } catch (Exception e) {
                        log.error("❌ Lỗi khi refresh token: {}", e.getMessage(), e);
                        return ResponseEntity.internalServerError().body(AuthResponseDto.builder()
                                        .success(false)
                                        .message("Lỗi hệ thống: " + e.getMessage())
                                        .build());
                }
        }

        @GetMapping("/me")
        public ResponseEntity<AuthResponseDto> getCurrentUser(HttpServletRequest request) {
                try {
                        String accessToken = getCookieValue(request, ACCESS_TOKEN_COOKIE);

                        if (accessToken == null) {
                                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                                .body(AuthResponseDto.builder()
                                                                .success(false)
                                                                .message("Chưa đăng nhập")
                                                                .build());
                        }

                        String username = authJwtService.extractUsername(accessToken);

                        if (!authJwtService.validateToken(accessToken, username)) {
                                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                                .body(AuthResponseDto.builder()
                                                                .success(false)
                                                                .message("Token không hợp lệ")
                                                                .build());
                        }

                        Optional<User> userOpt = userRepository.findByUsername(username);
                        if (userOpt.isEmpty()) {
                                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                                .body(AuthResponseDto.builder()
                                                                .success(false)
                                                                .message("User không tồn tại")
                                                                .build());
                        }

                        User user = userOpt.get();

                        return ResponseEntity.ok(AuthResponseDto.builder()
                                        .success(true)
                                        .message("Lấy thông tin thành công")
                                        .user(AuthResponseDto.UserInfoDto.builder()
                                                        .username(user.getUsername())
                                                        .name(user.getName())
                                                        .email(user.getEmail())
                                                        .build())
                                        .build());

                } catch (Exception e) {
                        log.error("❌ Lỗi: {}", e.getMessage());
                        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                        .body(AuthResponseDto.builder()
                                                        .success(false)
                                                        .message("Token không hợp lệ")
                                                        .build());
                }
        }

        /**
         * Logout - Clear cookies
         */
        @PostMapping("/logout")
        public ResponseEntity<ApiResponseDto> logout(
                        HttpServletRequest request,
                        HttpServletResponse response) {

                log.info("🚪 Logout request");

                try {
                        String refreshToken = getCookieValue(request, REFRESH_TOKEN_COOKIE);

                        if (refreshToken != null) {
                                String username = authJwtService.extractUsername(refreshToken);
                                authRefreshTokenRepository.revokeAllByUsername(username, LocalDateTime.now());
                                log.info("✅ Revoked tokens cho user: {}", username);
                        }

                        // Clear cookies
                        clearCookie(response, ACCESS_TOKEN_COOKIE);
                        clearCookie(response, REFRESH_TOKEN_COOKIE);

                        return ResponseEntity.ok(ApiResponseDto.builder()
                                        .success(true)
                                        .message("Đăng xuất thành công")
                                        .build());

                } catch (Exception e) {
                        log.error("❌ Lỗi logout: {}", e.getMessage());
                        return ResponseEntity.ok(ApiResponseDto.builder()
                                        .success(true)
                                        .message("Đăng xuất thành công")
                                        .build());
                }
        }

        /**
         * Helper: Clear cookie
         */
        private void clearCookie(HttpServletResponse response, String name) {
                Cookie cookie = new Cookie(name, null);
                cookie.setHttpOnly(true);
                cookie.setSecure(true);
                cookie.setPath("/");
                cookie.setMaxAge(0);
                response.addCookie(cookie);
        }

        /**
         * Helper: Get cookie value
         */
        private String getCookieValue(HttpServletRequest request, String name) {
                if (request.getCookies() != null) {
                        return Arrays.stream(request.getCookies())
                                        .filter(cookie -> name.equals(cookie.getName()))
                                        .map(Cookie::getValue)
                                        .findFirst()
                                        .orElse(null);
                }
                return null;
        }

        private HttpStatus mapPythonStatusCode(int statusCode) {
                return switch (statusCode) {
                        case 400 -> HttpStatus.BAD_REQUEST;
                        case 404 -> HttpStatus.NOT_FOUND;
                        case 500 -> HttpStatus.INTERNAL_SERVER_ERROR;
                        default -> HttpStatus.BAD_REQUEST;
                };
        }

        private void setSecureCookie(HttpServletResponse response, String name, String value, int maxAge) {
                Cookie cookie = new Cookie(name, value);
                cookie.setHttpOnly(true);
                cookie.setSecure(true); // Chỉ gửi qua HTTPS (production)
                cookie.setPath("/");
                cookie.setMaxAge(maxAge);
                cookie.setAttribute("SameSite", "None"); // CSRF protection + bật strict nếu đã có frontend + backend cùng domain
                response.addCookie(cookie);
        }
}