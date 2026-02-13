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
    private String username;
    private Instant expiresAt;
    private Instant issuedAt;
    private Instant revokedAt;

    public boolean isRevoked() {
        return revokedAt != null;
    }
}
