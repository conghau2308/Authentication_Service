package com.Authentication.AuthService.entity;

import java.time.LocalDateTime;

import org.hibernate.annotations.CreationTimestamp;

import com.Authentication.AuthService.enums.ClientRole;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.FetchType;
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
@Table(name = "oauth2_client_members", uniqueConstraints = @UniqueConstraint(columnNames = { "client_id",
        "user_id" }), indexes = {
                @Index(name = "idx_client", columnList = "client_id"),
                @Index(name = "idx_user", columnList = "user_id")
        })
@Builder
@NoArgsConstructor
@Data
@AllArgsConstructor
public class OAuth2ClientMember {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false)
    private OAuth2Client client;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_name", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    private ClientRole role;

    @CreationTimestamp
    @Column(name = "added_at", updatable = false)
    private LocalDateTime addedAt;

    @Column(name = "added_by")
    private String addedBy; // User ID của người thêm
}
