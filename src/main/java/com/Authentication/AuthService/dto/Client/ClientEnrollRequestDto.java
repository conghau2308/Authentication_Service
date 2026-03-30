package com.Authentication.AuthService.dto.client;

import lombok.Data;

@Data
public class ClientEnrollRequestDto {
    private String clientName;
    private String redirectUri;
}
