package com.Authentication.AuthService.dto.Client;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ClientSecretResponseDto {
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String secretValue;
    private String secretId;
    private String createdByUsername;
}
