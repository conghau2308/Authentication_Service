package com.Authentication.AuthService.controller;

import java.util.List;
import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.Authentication.AuthService.dto.PaginatedResponse;
import com.Authentication.AuthService.dto.response.ApiResponse;
import com.Authentication.AuthService.dto.user.AuthorizedApplicationResponseDto;
import com.Authentication.AuthService.dto.user.UpdateUserInforRequestDto;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.services.user.UserManageService;

import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
@Tag(name = "User management", description = "APIs for managing user information")
public class UserController {
    private final UserManageService userManageService;

    @PatchMapping("/update-infor")
    public ResponseEntity<ApiResponse<Void>> updateUserInfor(@Valid @RequestBody UpdateUserInforRequestDto requestDto,
            @AuthenticationPrincipal User user) {
        userManageService.updateUserInfor(user, requestDto);
        return ResponseEntity.ok(ApiResponse.success(null, "Cập nhật thông tin người dùng thành công."));
    }

    @GetMapping("/authorized-applications")
    public ResponseEntity<ApiResponse<PaginatedResponse<AuthorizedApplicationResponseDto>>> getAuthorizedApplications(
            @AuthenticationPrincipal User user,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int size) {
        PaginatedResponse<AuthorizedApplicationResponseDto> result = userManageService
                .getAuthorizedApplications(user, page, size);
        return ResponseEntity
                .ok(ApiResponse.success(result, "Lấy danh sách ứng dụng đã cấp quyền thành công."));
    }

    @DeleteMapping("/authorized-applications/{consent_id}/revoke")
    public ResponseEntity<ApiResponse<Void>> revokeApplicationConsent(@AuthenticationPrincipal User user,
            @PathVariable UUID consent_id) {
        userManageService.revokeApplicationConsent(user, consent_id);
        return ResponseEntity.ok(ApiResponse.success(null, "Thu hồi quyền ứng dụng thành công."));
    }

}
