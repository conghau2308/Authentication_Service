package com.Authentication.AuthService.dto;

import lombok.Data;

@Data
public class TokenRequestDto {
    private String grantType;
    private String clientId;
    private String clientSecret;
    private String code;
    private String redirectUri;
}