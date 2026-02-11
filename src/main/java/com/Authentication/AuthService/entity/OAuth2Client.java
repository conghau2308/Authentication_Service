package com.Authentication.AuthService.entity;

import java.time.LocalDateTime;

import org.hibernate.annotations.CreationTimestamp;

import com.Authentication.AuthService.enums.ClientType;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "oauth2_clients")
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2Client {
    @Id
    @Column(name = "client_id", nullable = false, length = 255)
    private String clientId;

    @Column(name = "client_name", nullable = false)
    private String clientName;

    @Enumerated(EnumType.STRING)
    @Column(name = "client_type", nullable = false, length = 50)
    private ClientType clientType;

    @Column(name = "redirect_uri", columnDefinition = "TEXT")
    private String redirectUri;

    @Column(name = "scopes", columnDefinition = "TEXT")
    private String scopes;

    @Column(name = "grant_Types", columnDefinition = "TEXT")
    private String grantTypes;

    @Column(name = "is_active")
    @Builder.Default
    private boolean isActive = true;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "created_by", nullable = false)
    private String createdBy; // User name của người tạo client
}
