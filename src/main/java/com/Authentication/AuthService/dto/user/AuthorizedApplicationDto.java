package com.Authentication.AuthService.dto.user;

import java.time.LocalDateTime;
import java.util.UUID;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class AuthorizedApplicationDto {
    // Consent
    private UUID id;
    private String grantedScopes;
    private LocalDateTime grantedAt;
    private LocalDateTime updatedAt;

    // Client Join
    private String clientName;
    // private String clientIcon;
}
