package com.Authentication.AuthService.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum RedisKeyPrefix {
    AUTH_CODE("auth_code:"),
    FAMILY_REFRESH_TOKEN_OAUTH("family_refresh_token_oauth:"),
    ACCESS_TOKEN_OAUTH("access_token_oauth:"),
    REFRESH_TOKEN_AUTH("refresh_token_auth:");

    private final String prefix;
}
