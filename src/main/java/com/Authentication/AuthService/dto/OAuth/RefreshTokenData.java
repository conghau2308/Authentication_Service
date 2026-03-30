package com.Authentication.AuthService.dto.oauth;

import java.io.Serializable;
import java.time.Instant;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshTokenData implements Serializable {
    private String tokenHashed;
    private String userId;
    private String clientId;
    private String scope;
    private Instant expiresAt;
    private Instant issuedAt;

    @Builder.Default
    private boolean revoked = false;

    private Instant revokedAt;

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public void revoke() {
        this.revoked = true;
        this.revokedAt = Instant.now();
    }
}
