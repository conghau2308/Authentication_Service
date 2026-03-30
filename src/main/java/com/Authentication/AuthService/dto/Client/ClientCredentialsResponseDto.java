package com.Authentication.AuthService.dto.client;

import java.util.List;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ClientCredentialsResponseDto {
    private String clientId;
    private List<ClientSecretDto> clientSecrets;
}
