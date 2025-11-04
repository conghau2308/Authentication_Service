package com.Authentication.AuthService.dto;

import java.util.Set;

public class CreateClientDto {
    private String appName;
    private Set<String> redirectUris;

    public String getAppName() {
        return appName;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }

    public Set<String> getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(Set<String> redirectUris) {
        this.redirectUris = redirectUris;
    }
}
