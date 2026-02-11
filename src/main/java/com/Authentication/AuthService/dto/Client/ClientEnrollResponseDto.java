package com.Authentication.AuthService.dto.Client;

import java.time.LocalDateTime;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ClientEnrollResponseDto {
    private String clientId;
    private String clientName;
    private String redirectUri;
    private LocalDateTime createdAt;
    private String ownerUsername;
}
