package com.Authentication.AuthService.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum GrantType {
    AUTHORIZATION_CODE("authorization_code", "Standard OAuth2 flow for web apps"),
    REFRESH_TOKEN("refresh_token", "Exchange refresh token for new access token");

    private final String value;
    private final String description;

    public static GrantType fromValue(String value) {
        for (GrantType type : values()) {
            if (type.value.equalsIgnoreCase(value)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Invalid GrantType: " + value);
    }
}
