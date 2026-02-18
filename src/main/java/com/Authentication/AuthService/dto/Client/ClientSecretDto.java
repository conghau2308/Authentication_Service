package com.Authentication.AuthService.dto.Client;

import java.time.LocalDateTime;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ClientSecretDto {
    private String secretId;
    private String maskedValue;
    private LocalDateTime createdAt;
    private UserOfClientResponseDto createdByUser;

    @Builder.Default
    private boolean isActive = true;
    @Builder.Default
    private LocalDateTime revokedAt = null;
    @Builder.Default
    private UserOfClientResponseDto revokedByUser = null;
}
