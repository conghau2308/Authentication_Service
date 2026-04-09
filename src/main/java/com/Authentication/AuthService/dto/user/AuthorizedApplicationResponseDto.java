package com.Authentication.AuthService.dto.user;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthorizedApplicationResponseDto {
    // Consent
    private UUID id;
    private List<String> grantedScopes;
    private LocalDateTime grantedAt;
    private LocalDateTime updatedAt;

    // Client Join
    private String clientName;
    // private String clientIcon;
}
