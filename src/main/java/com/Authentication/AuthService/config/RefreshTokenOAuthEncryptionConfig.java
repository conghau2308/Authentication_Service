package com.Authentication.AuthService.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Configuration
@Data
@ConfigurationProperties(prefix = "refresh-token.encryption")
public class RefreshTokenOAuthEncryptionConfig {
    private String secret;
}
