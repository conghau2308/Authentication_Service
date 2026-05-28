package com.Authentication.AuthService.entity;

import java.time.LocalDateTime;
import java.util.UUID;

import org.hibernate.annotations.CreationTimestamp;

import com.Authentication.AuthService.enums.ClientType;

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
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "oauth2_clients", indexes = {
        @Index(name = "idx_oauth2_clients_client_id", columnList = "client_id"),
        @Index(name = "idx_oauth2_clients_is_active", columnList = "is_active"),
        @Index(name = "idx_oauth2_clients_client_type", columnList = "client_type")
})
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2Client {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    // Lưu trữ UUID ở dạng 16bytes thay vì readable UUID(36 bytes) xxx-xxx-xxx... để
    // tiết kiệm bộ nhớ nhưng số lượng vẫn như nhau
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "client_id", nullable = false, length = 255)
    private String clientId;

    @Column(name = "client_name", nullable = false, length = 255)
    private String clientName;

    @Enumerated(EnumType.STRING)
    @Column(name = "client_type", nullable = false, length = 50)
    private ClientType clientType;

    @Column(name = "redirect_uri", nullable = false, columnDefinition = "TEXT")
    private String redirectUri;

    @Column(name = "scopes", columnDefinition = "TEXT")
    private String scopes;

    @Column(name = "grant_types", columnDefinition = "TEXT")
    private String grantTypes;

    @Column(name = "is_active")
    @Builder.Default
    private boolean isActive = true;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by")
    private User createdBy;
}
