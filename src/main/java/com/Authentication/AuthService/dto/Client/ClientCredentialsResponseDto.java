package com.Authentication.AuthService.dto.Client;

import java.util.List;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ClientCredentialsResponseDto {
    private String clientId;
    private List<ClientSecretDto> clientSecrets;
}
