package com.Authentication.AuthService.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.Authentication.AuthService.dto.invitation.AcceptInvitationResponseDto;
import com.Authentication.AuthService.dto.invitation.InvitationPreviewDto;
import com.Authentication.AuthService.dto.response.ApiResponse;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.services.invitation.InvitationService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/invitations")
@RequiredArgsConstructor
@Tag(name = "Client Invitations", description = "APIs quản lý lời mời thành viên")
public class InvitationController {

    private final InvitationService invitationService;

    // ── Public: xem thông tin invitation trước khi confirm ───────
    // Không cần auth — invitee có thể chưa đăng nhập khi click link

    @GetMapping("/preview")
    @Operation(summary = "Xem thông tin lời mời (public)")
    public ResponseEntity<ApiResponse<InvitationPreviewDto>> previewInvitation(
            @RequestParam String token) {

        InvitationPreviewDto preview = invitationService.getInvitationPreview(token);
        return ResponseEntity.ok(ApiResponse.success(preview, "Lấy thông tin lời mời thành công."));
    }

    // ── Auth required: invitee chấp nhận ─────────────────────────

    @PostMapping("/accept")
    @Operation(summary = "Chấp nhận lời mời")
    public ResponseEntity<ApiResponse<AcceptInvitationResponseDto>> acceptInvitation(
            @RequestParam String token,
            @AuthenticationPrincipal User user) {

        AcceptInvitationResponseDto result = invitationService.acceptInvitation(token, user);
        return ResponseEntity.ok(ApiResponse.success(result, "Bạn đã tham gia ứng dụng thành công."));
    }

    // ── Auth required: invitee từ chối ────────────────────────────

    @PostMapping("/decline")
    @Operation(summary = "Từ chối lời mời")
    public ResponseEntity<ApiResponse<Void>> declineInvitation(
            @RequestParam String token,
            @AuthenticationPrincipal User user) {

        invitationService.declineInvitation(token, user);
        return ResponseEntity.ok(ApiResponse.success(null, "Đã từ chối lời mời."));
    }
}