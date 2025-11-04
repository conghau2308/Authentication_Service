package com.Authentication.AuthService.dto;

public class ClientSecretDto {
    private String clienId;
    private String clientSecret;

    public ClientSecretDto(String clientId, String clientSecret) {
        this.clienId = clientId;
        this.clientSecret = clientSecret;
    }

    public String getClientId() {
        return clienId;
    }

    public String getClientSecret() {
        return clientSecret;
    }
}
