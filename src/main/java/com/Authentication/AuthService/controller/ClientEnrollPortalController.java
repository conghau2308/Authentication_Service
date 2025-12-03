package com.Authentication.AuthService.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.*;

import com.Authentication.AuthService.dto.ClientSecretDto;
import com.Authentication.AuthService.dto.CreateClientDto;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.services.enrollment.ClientManagementService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/portal/api/v1/enroll")
@RequiredArgsConstructor
@Slf4j
public class ClientEnrollPortalController {

    private final ClientManagementService clientService;

    /**
     * ✅ Đăng ký OAuth2 Client mới
     * Yêu cầu: User phải đã đăng nhập (face auth + session hợp lệ)
     */
    @PostMapping
    public ResponseEntity<?> registerNewClient(
            @Valid @RequestBody CreateClientDto createClientDto,
            @AuthenticationPrincipal User user,
            HttpServletRequest request) {

        log.info("📝 Nhận yêu cầu đăng ký client mới");

        // ✅ Debug logging
        HttpSession session = request.getSession(false);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // ✅ LOG CHI TIẾT
        log.info("🔍 Request Headers:");
        request.getHeaderNames().asIterator()
                .forEachRemaining(header -> log.info("   {}: {}", header, request.getHeader(header)));

        log.info("🔍 Cookies:");
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                log.info("   {}: {}", cookie.getName(), cookie.getValue());
            }
        } else {
            log.warn("   ❌ Không có cookie nào được gửi!");
        }

        log.info("🔍 Session info:");
        log.info("   - Session exists: {}", session != null);
        if (session != null) {
            log.info("   - Session ID: {}", session.getId());
            log.info("   - Is new: {}", session.isNew());
        }

        log.info("🔍 Authentication: {}", auth);
        log.info("🔍 User from @AuthenticationPrincipal: {}", user);

        if (user == null) {
            log.error("❌ User is null - Session không hợp lệ hoặc cookie không được gửi");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(createErrorResponse("unauthorized", "Vui lòng đăng nhập lại"));
        }

        try {
            log.info("✅ User authenticated: {} (ID: {}, Email: {})",
                    user.getUsername(), user.getId(), user.getEmail());

            // 2. Tạo client
            RegisteredClient clientWithRawSecret = clientService.createClient(createClientDto, user);

            // 3. Tạo response DTO
            ClientSecretDto responseDto = new ClientSecretDto(
                    clientWithRawSecret.getClientId(),
                    clientWithRawSecret.getClientSecret());

            log.info("✅ Client đã được tạo thành công - Client ID: {} cho User: {}",
                    clientWithRawSecret.getClientId(), user.getUsername());

            // 4. Trả về response với thông tin bổ sung
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Client đã được tạo thành công");
            response.put("client_id", responseDto.getClientId());
            response.put("client_secret", responseDto.getClientSecret());
            response.put("client_name", clientWithRawSecret.getClientName());
            response.put("owner", user.getUsername());
            response.put("warning", "⚠️ QUAN TRỌNG: Client Secret chỉ hiển thị một lần. Vui lòng lưu lại ngay!");

            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (IllegalArgumentException e) {
            log.error("❌ Validation error: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(createErrorResponse("validation_error", e.getMessage()));

        } catch (Exception e) {
            log.error("❌ Lỗi khi tạo client: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("server_error", "Lỗi server khi tạo client: " + e.getMessage()));
        }
    }

    /**
     * ✅ Kiểm tra user đã đăng nhập chưa
     */
    @GetMapping("/check-auth")
    public ResponseEntity<?> checkAuthentication(@AuthenticationPrincipal User user) {
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(createErrorResponse("unauthorized", "Chưa đăng nhập"));
        }

        Map<String, Object> response = new HashMap<>();
        response.put("authenticated", true);
        response.put("user_id", user.getId());
        response.put("username", user.getUsername());
        response.put("name", user.getName());
        response.put("email", user.getEmail());
        response.put("enrolled_at", user.getEnrolledAt());
        response.put("last_verified_at", user.getLastVerifiedAt());

        return ResponseEntity.ok(response);
    }

    /**
     * ✅ Lấy thông tin user hiện tại
     */
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@AuthenticationPrincipal User user) {
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(createErrorResponse("unauthorized", "Chưa đăng nhập"));
        }

        Map<String, Object> response = new HashMap<>();
        response.put("id", user.getId());
        response.put("username", user.getUsername());
        response.put("name", user.getName());
        response.put("email", user.getEmail());
        response.put("enrolled_at", user.getEnrolledAt());
        response.put("last_verified_at", user.getLastVerifiedAt());

        return ResponseEntity.ok(response);
    }

    // Helper method
    private Map<String, String> createErrorResponse(String error, String message) {
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("error", error);
        errorResponse.put("message", message);
        return errorResponse;
    }
}