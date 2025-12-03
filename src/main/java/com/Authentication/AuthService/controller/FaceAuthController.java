package com.Authentication.AuthService.controller;

import com.Authentication.AuthService.dto.ApiResponseDto;
import com.Authentication.AuthService.dto.EnrollRequestDto;
import com.Authentication.AuthService.dto.EnrollResponseDto;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.repository.UserRepository;
import com.Authentication.AuthService.services.auth.FaceAuthService;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/face-auth")
@Slf4j
@RequiredArgsConstructor
public class FaceAuthController {
    private final FaceAuthService faceAuthService;
    private final UserRepository userRepository;

    /**
     * Endpoint đăng ký khuôn mặt (Blocking)
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
                        .build());
            }

            if (userRepository.existsByEmail(request.getEmail())) {
                return ResponseEntity.badRequest().body(ApiResponseDto.builder()
                        .success(false)
                        .message("Email đã được sử dụng")
                        .build());
            }

            EnrollResponseDto enrollResponse = faceAuthService.enrollUser(request.getUsername());

            if (enrollResponse != null) {
                User user = User.builder()
                        .username(request.getUsername())
                        .name(request.getName())
                        .email(request.getEmail())
                        .helperData(enrollResponse.getHelper_data_b64())
                        .keyHash(enrollResponse.getKey_hash_b64())
                        .build();

                userRepository.save(user);

                log.info("✅ Đăng ký khuôn mặt thành công và đã lưu DB cho user: {}", request.getUsername());

                return ResponseEntity.ok(ApiResponseDto.builder()
                        .success(true)
                        .message("Đăng ký khuôn mặt thành công")
                        .build());
            } else {
                return ResponseEntity.badRequest().body(ApiResponseDto.builder()
                        .success(false)
                        .message("Đăng ký khuôn mặt thất bại. Vui lòng thử lại.")
                        .build());
            }

        } catch (Exception e) {
            log.error("❌ Lỗi khi đăng ký khuôn mặt: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(ApiResponseDto.builder()
                    .success(false)
                    .message("Lỗi server: " + e.getMessage())
                    .build());
        }
    }

    /**
     * ✅ Endpoint verify khuôn mặt - FIXED SESSION PERSISTENCE
     */
    @PostMapping("/verify/{username}")
    public ResponseEntity<ApiResponseDto> verifyFace(
            @PathVariable String username,
            HttpServletRequest request) {

        log.info("🔍 Nhận yêu cầu xác thực khuôn mặt cho user: {}", username);

        try {
            Optional<User> userOpt = userRepository.findByUsername(username);

            if (userOpt.isEmpty()) {
                return ResponseEntity.badRequest().body(ApiResponseDto.builder()
                        .success(false)
                        .message("User chưa đăng ký khuôn mặt")
                        .build());
            }

            User user = userOpt.get();

            boolean verified = faceAuthService.verifyUser(
                    username,
                    user.getHelperData(),
                    user.getKeyHash());

            // Nhớ sửa lại verified
            if (verified) {
                user.setLastVerifiedAt(LocalDateTime.now());
                userRepository.save(user);

                // ✅ TẠO AUTHENTICATION VỚI USER ENTITY TRỰC TIẾP
                Authentication authentication = new UsernamePasswordAuthenticationToken(
                        user, // ✅ Dùng User entity trực tiếp, không qua UserDetailsService
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_USER")));

                // ✅ Tạo SecurityContext mới
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(authentication);
                SecurityContextHolder.setContext(context);

                // ✅ Tạo session mới và lưu context
                HttpSession session = request.getSession(true);
                session.setAttribute(
                        HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                        context);

                // ✅ Log chi tiết để debug
                log.info("✅ Session created:");
                log.info("   - Session ID: {}", session.getId());
                log.info("   - Max Inactive Interval: {} seconds", session.getMaxInactiveInterval());
                log.info("   - Creation Time: {}", new java.util.Date(session.getCreationTime()));
                log.info("   - Is New: {}", session.isNew());
                log.info("   - User: {} (ID: {})", user.getUsername(), user.getId());
                log.info("   - Authentication: {}", authentication.getName());
                log.info("   - Authorities: {}", authentication.getAuthorities());

                return ResponseEntity.ok(ApiResponseDto.builder()
                        .success(true)
                        .message("Xác thực khuôn mặt thành công")
                        .build());
            } else {
                return ResponseEntity.ok(ApiResponseDto.builder()
                        .success(false)
                        .message("Xác thực khuôn mặt thất bại")
                        .build());
            }

        } catch (Exception e) {
            log.error("❌ Lỗi khi xác thực khuôn mặt: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(ApiResponseDto.builder()
                    .success(false)
                    .message("Lỗi server: " + e.getMessage())
                    .build());
        }
    }

    /**
     * Endpoint đăng ký khuôn mặt (Non-blocking Reactive)
     */
    @PostMapping("/enroll-async")
    public Mono<ResponseEntity<ApiResponseDto>> enrollFaceAsync(@Valid @RequestBody EnrollRequestDto request) {
        log.info("📝 [ASYNC] Nhận yêu cầu đăng ký khuôn mặt cho user: {} (name: {}, email: {})",
                request.getUsername(), request.getName(), request.getEmail());

        if (userRepository.existsByUsername(request.getUsername())) {
            return Mono.just(ResponseEntity.badRequest().body(ApiResponseDto.builder()
                    .success(false)
                    .message("Username đã được sử dụng")
                    .build()));
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            return Mono.just(ResponseEntity.badRequest().body(ApiResponseDto.builder()
                    .success(false)
                    .message("Email đã được sử dụng")
                    .build()));
        }

        return faceAuthService.enrollUserAsync(request.getUsername())
                .flatMap(enrollResponse -> {
                    User user = User.builder()
                            .username(request.getUsername())
                            .name(request.getName())
                            .email(request.getEmail())
                            .helperData(enrollResponse.getHelper_data_b64())
                            .keyHash(enrollResponse.getKey_hash_b64())
                            .build();

                    userRepository.save(user);

                    log.info("✅ [ASYNC] Đăng ký khuôn mặt thành công và đã lưu DB cho user: {}", request.getUsername());

                    return Mono.just(ResponseEntity.ok(ApiResponseDto.builder()
                            .success(true)
                            .message("Đăng ký khuôn mặt thành công")
                            .build()));
                })
                .onErrorResume(error -> {
                    log.error("❌ [ASYNC] Lỗi khi đăng ký khuôn mặt: {}", error.getMessage());
                    return Mono.just(ResponseEntity.badRequest().body(ApiResponseDto.builder()
                            .success(false)
                            .message("Đăng ký khuôn mặt thất bại: " + error.getMessage())
                            .build()));
                });
    }

    /**
     * Endpoint verify async
     */
    @PostMapping("/verify-async/{username}")
    public Mono<ResponseEntity<ApiResponseDto>> verifyFaceAsync(
            @PathVariable String username,
            HttpServletRequest request) {

        log.info("🔍 [ASYNC] Nhận yêu cầu xác thực khuôn mặt cho user: {}", username);

        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isEmpty()) {
            return Mono.just(ResponseEntity.badRequest().body(ApiResponseDto.builder()
                    .success(false)
                    .message("User chưa đăng ký khuôn mặt")
                    .build()));
        }

        User user = userOpt.get();

        return faceAuthService.verifyUserAsync(username, user.getHelperData(), user.getKeyHash())
                .flatMap(verified -> {
                    if (verified) {
                        user.setLastVerifiedAt(LocalDateTime.now());
                        userRepository.save(user);

                        // Tạo authentication và session
                        Authentication authentication = new UsernamePasswordAuthenticationToken(
                                user,
                                null,
                                List.of(new SimpleGrantedAuthority("ROLE_USER")));

                        SecurityContext context = SecurityContextHolder.createEmptyContext();
                        context.setAuthentication(authentication);
                        SecurityContextHolder.setContext(context);

                        HttpSession session = request.getSession(true);
                        session.setAttribute(
                                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                                context);

                        log.info("✅ [ASYNC] Xác thực khuôn mặt thành công và đã tạo session cho user: {}", username);

                        return Mono.just(ResponseEntity.ok(ApiResponseDto.builder()
                                .success(true)
                                .message("Xác thực khuôn mặt thành công")
                                .build()));
                    } else {
                        return Mono.just(ResponseEntity.ok(ApiResponseDto.builder()
                                .success(false)
                                .message("Xác thực khuôn mặt thất bại")
                                .build()));
                    }
                })
                .onErrorResume(error -> {
                    log.error("❌ [ASYNC] Lỗi khi xác thực khuôn mặt: {}", error.getMessage());
                    return Mono.just(ResponseEntity.internalServerError().body(ApiResponseDto.builder()
                            .success(false)
                            .message("Lỗi server: " + error.getMessage())
                            .build()));
                });
    }
}