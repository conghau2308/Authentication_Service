package com.Authentication.AuthService.dto.Auth;

import java.time.Instant;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RefreshTokenData {
    private String userId;
    private Instant expiresAt;
    private Instant issuedAt;
    @Builder.Default
    private Instant revokedAt = null;

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
}
