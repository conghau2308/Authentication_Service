package com.Authentication.AuthService.entity;

import java.time.LocalDateTime;

import org.hibernate.annotations.CreationTimestamp;

import com.Authentication.AuthService.enums.ClientRole;

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
@Table(name = "oauth2_client_members", indexes = {
                @Index(name = "idx_members_client_id", columnList = "client_id"),
                @Index(name = "idx_members_user_id", columnList = "user_id"),
                @Index(name = "idx_members_is_active", columnList = "is_active"),
                @Index(name = "idx_members_client_user_active", columnList = "client_id, user_id, is_active")
}, uniqueConstraints = {
                @UniqueConstraint(name = "uk_client_user", columnNames = { "client_id", "user_id" })
})
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2ClientMember {

        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        @Column(name = "id", nullable = false, updatable = false)
        private Long id;

        @ManyToOne(fetch = FetchType.LAZY)
        @JoinColumn(name = "client_id", nullable = false)
        private OAuth2Client client;

        @ManyToOne(fetch = FetchType.LAZY)
        @JoinColumn(name = "user_id", nullable = false)
        private User user;

        @Enumerated(EnumType.STRING)
        @Column(name = "role", nullable = false, length = 50)
        private ClientRole role;

        @Column(name = "is_active", nullable = false)
        @Builder.Default
        private boolean isActive = true;

        @CreationTimestamp
        @Column(name = "added_at", nullable = false, updatable = false)
        private LocalDateTime addedAt;

        @ManyToOne(fetch = FetchType.LAZY)
        @JoinColumn(name = "added_by")
        private User addedBy;

        // Business methods
        public void deactivate() {
                this.isActive = false;
        }

        public void activate() {
                this.isActive = true;
        }
}