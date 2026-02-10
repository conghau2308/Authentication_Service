package com.Authentication.AuthService.entity;

import java.time.LocalDateTime;

import org.hibernate.annotations.CreationTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.persistence.FetchType;

@Entity
@Table(name = "oauth2_client_secrets", indexes = {
    @Index(name = "idx_client_id", columnList = "client_id")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2ClientSecret {
    @Id
    @Column(name = "secret_id", length = 255)
    private String secretId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false)
    private OAuth2Client client;

    @Column(name = "secret_hash", nullable = false)
    private String secretHash;

    @Column(name = "secret_hint", nullable = false)
    private String secretHint;

    @Column(name = "is_active")
    @Builder.Default
    private boolean isActive = true;

    @Column(name = "created_by", nullable = false, updatable = false)
    private String createdBy; // User name của người tạo secret

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;
    
    @Column(name = "revoke_by")
    private String revokedBy; // User name của người thu hồi

    public boolean isValid() {
        return isActive && (revokedAt == null);
    }

    public void revoke(String userName) {
        this.isActive = false;
        this.revokedAt = LocalDateTime.now();
        this.revokedBy = userName;
    }
}
