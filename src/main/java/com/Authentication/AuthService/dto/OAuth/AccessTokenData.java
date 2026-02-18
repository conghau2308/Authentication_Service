package com.Authentication.AuthService.dto.OAuth;

import java.time.Instant;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AccessTokenData {
    private String userId;
    private String clientId;
    private String scope;
    private Instant expiresAt;
    @Builder.Default
    private Instant issuedAt = Instant.now();
}
