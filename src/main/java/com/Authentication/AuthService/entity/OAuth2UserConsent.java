package com.Authentication.AuthService.entity;

import java.time.LocalDateTime;
import java.util.UUID;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "oauth2_user_consents", indexes = {
        @Index(name = "idx_consents_user_id", columnList = "user_id"),
        @Index(name = "idx_consents_client_id", columnList = "client_id"),
}, uniqueConstraints = {
        @UniqueConstraint(name = "uk_consent_user_client", columnNames = { "user_id", "client_id" })
})
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2UserConsent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false, columnDefinition = "BINARY(16)")
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false, updatable = false)
    private OAuth2Client client;

    @Column(name = "granted_scopes", nullable = false, columnDefinition = "TEXT")
    private String grantedScopes;

    @CreationTimestamp
    @Column(name = "granted_at", nullable = false, updatable = false)
    private LocalDateTime grantedAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}