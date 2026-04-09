package com.Authentication.AuthService.dto.client;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ClientSecretResponseDto {
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private String secretValue;
    private String secretId;
}
