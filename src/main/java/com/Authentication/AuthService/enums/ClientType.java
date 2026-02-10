package com.Authentication.AuthService.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ClientType {
    CONFIDENTIAL("confidential", "Web applications with secure backend that can store secrets", true),
    PUBLIC("public", "Mobile/SPA/Desktop apps that cannot securely store secrets", false);
    
    private final String value;
    private final String description;
    private final boolean requiredSecret;
}
