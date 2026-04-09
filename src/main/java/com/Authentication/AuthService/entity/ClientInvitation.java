package com.Authentication.AuthService.entity;

import java.time.LocalDateTime;
import java.util.UUID;

import org.hibernate.annotations.CreationTimestamp;

import com.Authentication.AuthService.enums.ClientRole;
import com.Authentication.AuthService.enums.InvitationStatus;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
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
@Table(name = "client_invitations", indexes = {
        @Index(name = "idx_invitation_token", columnList = "token"),
        @Index(name = "idx_invitation_client_id", columnList = "client_id"),
        @Index(name = "idx_invitation_email", columnList = "invitee_email"),
        @Index(name = "idx_invitation_status", columnList = "status"),
        @Index(name = "idx_invitation_expires_at", columnList = "expires_at"),
}, uniqueConstraints = {
        // Mỗi email chỉ có 1 PENDING invitation cho 1 client tại 1 thời điểm
        // Partial unique index — chỉ enforce khi status = PENDING
        // Nếu DB không hỗ trợ partial unique thì validate ở service layer
        @UniqueConstraint(name = "uq_invitation_pending", columnNames = { "client_id", "invitee_email", "status" })
})
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ClientInvitation {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false, columnDefinition = "BINARY(16)")
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false)
    private OAuth2Client client;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "invited_by", nullable = false)
    private User invitedBy;

    @Column(name = "invitee_email", nullable = false, length = 255)
    private String inviteeEmail;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false, length = 20)
    private ClientRole role;

    // Token random 32 bytes hex — dùng để verify khi invitee click link
    @Column(name = "token", nullable = false, unique = true, length = 64)
    private String token;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    @Builder.Default
    private InvitationStatus status = InvitationStatus.PENDING;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "accepted_at")
    private LocalDateTime acceptedAt;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    // ── Business methods ──────────────────────────────────────────

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(this.expiresAt);
    }

    public boolean isPending() {
        return this.status == InvitationStatus.PENDING;
    }

    public void accept() {
        this.status = InvitationStatus.ACCEPTED;
        this.acceptedAt = LocalDateTime.now();
    }

    public void decline() {
        this.status = InvitationStatus.DECLINED;
    }

    public void revoke() {
        this.status = InvitationStatus.REVOKED;
    }

    public void markExpired() {
        this.status = InvitationStatus.EXPIRED;
    }
}