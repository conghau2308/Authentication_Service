package com.Authentication.AuthService.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "cookie")
public class CookieConfig {
    private String accessTokenName;
    private int accessTokenMaxAge; // giây
    private String refreshTokenName;
    private int refreshTokenMaxAge; // giây
}
