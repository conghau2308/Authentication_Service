package com.Authentication.AuthService.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum RedisKeyPrefix {
    AUTH_CODE("auth_code:"),
    REFRESH_TOKEN_OAUTH("refresh_token_oauth:"),
    REFRESH_TOKEN_AUTH("refresh_token_auth:");

    private final String prefix;
}
