package com.Authentication.AuthService.dto.invitation;

import java.time.LocalDateTime;
import java.util.UUID;

import com.Authentication.AuthService.enums.ClientRole;
import com.Authentication.AuthService.enums.InvitationStatus;

import lombok.Builder;
import lombok.Data;

// ── Response: danh sách pending invitations trên UI ──────────────
@Data
@Builder
public class PendingInvitationDto {
    private UUID invitationId;
    private String inviteeEmail;
    private ClientRole role;
    private InvitationStatus status;
    private LocalDateTime expiresAt;
    private LocalDateTime createdAt;
    private String invitedByName;
}