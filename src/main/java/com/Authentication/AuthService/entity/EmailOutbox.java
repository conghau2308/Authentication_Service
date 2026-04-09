package com.Authentication.AuthService.entity;

import java.time.LocalDateTime;
import java.util.UUID;

import org.hibernate.annotations.CreationTimestamp;

import com.Authentication.AuthService.enums.EmailStatus;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "email_outbox", indexes = {
        @Index(name = "idx_outbox_status", columnList = "status"),
        @Index(name = "idx_outbox_created_at", columnList = "created_at"),
        @Index(name = "idx_outbox_retry_count", columnList = "retry_count"),
})
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class EmailOutbox {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    // Tên template Thymeleaf — vd: "email/invitation"
    @Column(name = "template_name", nullable = false, length = 100)
    private String templateName;

    @Column(name = "to_email", nullable = false, length = 255)
    private String toEmail;

    @Column(name = "subject", nullable = false, length = 255)
    private String subject;

    // JSON string chứa tất cả variables cần render template
    @Column(name = "payload", nullable = false, columnDefinition = "TEXT")
    private String payload;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    @Builder.Default
    private EmailStatus status = EmailStatus.PENDING;

    @Column(name = "retry_count", nullable = false)
    @Builder.Default
    private int retryCount = 0;

    @Column(name = "last_tried_at")
    private LocalDateTime lastTriedAt;

    // Lưu message lỗi cuối để debug
    @Column(name = "last_error", columnDefinition = "TEXT")
    private String lastError;

    @Column(name = "sent_at")
    private LocalDateTime sentAt;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    // ── Business methods ──────────────────────────────────────────

    public void markSent() {
        this.status = EmailStatus.SENT;
        this.sentAt = LocalDateTime.now();
        this.lastError = null;
    }

    public void recordFailure(String errorMessage, int maxRetry) {
        this.retryCount += 1;
        this.lastTriedAt = LocalDateTime.now();
        this.lastError = errorMessage;
        if (this.retryCount >= maxRetry) {
            this.status = EmailStatus.FAILED;
        }
    }
}