package com.Authentication.AuthService.dto.Client;

import java.time.LocalDateTime;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ClientSecretDto {
    private String secretId;
    private String maskedValue;
    private LocalDateTime createAt;
    private String createdByUserName;
    private boolean isActive;
    private String revokedByUserName;
}
