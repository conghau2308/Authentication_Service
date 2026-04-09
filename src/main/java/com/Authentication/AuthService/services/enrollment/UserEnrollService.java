package com.Authentication.AuthService.services.enrollment;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import com.Authentication.AuthService.config.CookieConfig;
import com.Authentication.AuthService.dto.UserEnrollRequestDto;
import com.Authentication.AuthService.dto.UserEnrollResponseDto;
import com.Authentication.AuthService.dto.UserVerifyRequestDto;
import com.Authentication.AuthService.dto.auth.RefreshTokenData;
import com.Authentication.AuthService.dto.user.UserInforResponseDto;
import com.Authentication.AuthService.dto.user.UsernameAvailabilityDto;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.exception.business.BusinessException;
import com.Authentication.AuthService.repository.UserRepository;
import com.Authentication.AuthService.services.auth.AuthJwtService;
import com.Authentication.AuthService.services.auth.FaceAuthService;
import com.Authentication.AuthService.services.auth.RefreshTokenService;
import com.Authentication.AuthService.services.cookies.CookiesService;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserEnrollService {
    private final UserRepository userRepository;
    private final FaceAuthService faceAuthService;
    private final AuthJwtService authJwtService;
    private final CookiesService cookiesService;
    private final CookieConfig cookieConfig;
    private final RefreshTokenService refreshTokenService;

    @Transactional
    public void enroll(UserEnrollRequestDto request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new BusinessException("USERNAME_EXISTS", "Username đã được sử dụng.");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new BusinessException("EMAIL_EXISTS", "Email đã được sử dụng.");
        }

        if (request.getImage_b64() == null || request.getImage_b64().isBlank()) {
            throw new BusinessException("IMAGE_REQUIRED", "Vui lòng gửi ảnh khuôn mặt.");
        }

        // UserEnrollResponseDto response =
        // faceAuthService.enrollUser(request.getUsername(), request.getImage_b64());

        // ── FAKE RESPONSE để test ──────────────────────────────
        UserEnrollResponseDto response = UserEnrollResponseDto.builder()
                .helper_data_b64("FAKE_HELPER_DATA_" + request.getUsername())
                .key_hash_b64("FAKE_KEY_HASH_" + request.getUsername())
                .build();
        // ───────────────────────────────────────────────────────

        if (response == null) {
            throw new BusinessException("ENROLL_FAILED", "Đăng ký khuôn mặt không thành công.");
        }

        User user = User.builder()
                .username(request.getUsername())
                .name(request.getName())
                .email(request.getEmail())
                .helperData(response.getHelper_data_b64())
                .keyHash(response.getKey_hash_b64())
                .build();

        userRepository.save(user);
    }

    @Transactional
    public String verify(UserVerifyRequestDto request, HttpServletResponse response) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new BusinessException("USER_NOT_FOUND", "User chưa đăng ký tài khoản."));

        if (request.getImageBase64() == null || request.getImageBase64().isBlank()) {
            throw new BusinessException("IMAGE_REQUIRED", "Vui lòng gửi ảnh khuôn mặt.");
        }

        // boolean result = faceAuthService.verifyUser(request.getUsername(),
        // request.getImageBase64(),
        // user.getHelperData(), user.getKeyHash());
        boolean result = true;

        if (result) {
            // Cập nhật lần verify mới nhất
            user.setLastVerifiedAt(LocalDateTime.now()); // Chú ý thời gian trong local và production
            userRepository.save(user);

            // Tạo access Token
            String accessToken = authJwtService.generateAccessToken(
                    user.getId().toString(),
                    user.getEmail(),
                    user.getName());
            // Tạo refresh token
            String refreshToken = authJwtService.generateRefreshToken(user.getId().toString());

            // Lưu refresh token mới
            RefreshTokenData refreshtokensaved = RefreshTokenData.builder()
                    .userId(user.getId().toString())
                    .issuedAt(Instant.now())
                    .expiresAt(Instant.now().plusSeconds(cookieConfig.getRefreshTokenMaxAge()))
                    .build();
            refreshTokenService.saveRefreshTokenToRedis(refreshToken, refreshtokensaved);

            // Set cookie http-only cho access token vaf refresh token
            cookiesService.setSecureAllCookies(response, accessToken, refreshToken);

            return accessToken;
        } else {
            throw new BusinessException("VERIFY_FAILED", "Xác thực không thành công. Vui lòng thử lại.");
        }
    }

    public void refresh(String refreshToken, HttpServletResponse response) {
        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new BusinessException("TOKEN_IS_NULL", "Vui lòng gửi Refresh token đã cấp.");
        }

        if (!authJwtService.validateRefreshToken(refreshToken)) {
            throw new BusinessException("INVALID_TOKEN", "Refresh token không hợp lệ hoặc đã hết hạn.");
        }

        // Kiểm tra nếu refresh token còn hạn thì không revoke
        // RefreshTokenData refreshTokenOpt = refreshTokenService.getRefreshTokenDataFromRedis(refreshToken);
        // // Chú ý phần isexpired có cần thiết không
        // if (refreshTokenOpt.isRevoked() || refreshTokenOpt.isExpired()) {
        //     throw new BusinessException("TOKEN_REVOKED", "Refresh token đã bị thu hồi.", HttpStatus.UNAUTHORIZED);
        // }

        // Tạo access token mới
        UUID userId = UUID.fromString(authJwtService.extractUserId(refreshToken));
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException("USER_NOT_FOUND", "Không tùm thấy user phù hợp."));
        if (!user.isActive()) {
            throw new BusinessException("INVALID_USER", "User đã bị cấm trên hệ thống.", HttpStatus.FORBIDDEN);
        }
        String accessToken = authJwtService.generateAccessToken(user.getId().toString(), user.getEmail(),
                user.getName());
        cookiesService.setSecureAccessCookie(response, accessToken);
    }

    public void logout(String refreshToken, HttpServletResponse response) {
        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new BusinessException("TOKEN_IS_NULL", "Vui lòng gửi Refresh token đã cấp.", HttpStatus.UNAUTHORIZED);
        }

        cookiesService.clearAllCookies(response);
    }

    public UsernameAvailabilityDto checkUsernameAvailability(String username) {
        boolean isAvailable = !userRepository.existsByUsername(username);
        return UsernameAvailabilityDto.builder()
                .available(isAvailable)
                .build();
    }
}
