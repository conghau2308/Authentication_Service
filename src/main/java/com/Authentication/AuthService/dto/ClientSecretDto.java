package com.Authentication.AuthService.dto;

public class ClientSecretDto {
    private String clientId;
    private String clientSecret;

    public ClientSecretDto(String clientId, String clientSecret) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }
}
