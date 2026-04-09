package com.Authentication.AuthService.dto.client;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UpdateClientRequestDto {
    private String clientName;

    private String redirectUri;
}
