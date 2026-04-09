package com.Authentication.AuthService.dto.invitation;

import java.util.UUID;

import com.Authentication.AuthService.enums.ClientRole;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

// ── Request: OWNER/ADMIN gửi invitation ──────────────────────────
@Data
public class SendInvitationRequestDto {

    @NotNull(message = "User ID không được để trống.")
    private UUID userId;

    @NotNull(message = "Role không được để trống.")
    private ClientRole role; // Chỉ chấp nhận ADMIN hoặc DEVELOPER — validate ở service
}