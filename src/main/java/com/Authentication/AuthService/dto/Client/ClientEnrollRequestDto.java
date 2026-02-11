package com.Authentication.AuthService.dto.Client;

import lombok.Data;

@Data
public class ClientEnrollRequestDto {
    private String clientName;
    private String redirectUri;
}
