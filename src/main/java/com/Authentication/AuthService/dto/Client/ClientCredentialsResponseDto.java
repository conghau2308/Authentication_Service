package com.Authentication.AuthService.dto.client;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import com.Authentication.AuthService.enums.ClientRole;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ClientCredentialsResponseDto {
    private UUID id;
    private String clientId;
    private String clientName;
    private String redirectUri;
    private String clientIcon;
    private String clientHomePageUrl;
    private LocalDateTime createdAt;
    private ClientRole role;
    private List<ClientSecretDto> clientSecrets;
}
