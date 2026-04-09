package com.Authentication.AuthService.dto.invitation;

import java.time.LocalDateTime;

import com.Authentication.AuthService.enums.ClientRole;

import lombok.Builder;
import lombok.Data;

// ── Response: thông tin hiển thị trên trang confirm của invitee ──
@Data
@Builder
public class InvitationPreviewDto {
    private String clientName;
    // private String clientIcon;
    private ClientRole role;
    private String invitedByName;
    private String invitedByEmail;
    private String inviteeEmail;
    private LocalDateTime expiresAt;
}