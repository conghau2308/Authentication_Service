package com.Authentication.AuthService.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.Authentication.AuthService.entity.EmailOutbox;
import com.Authentication.AuthService.enums.EmailStatus;

@Repository
public interface EmailOutboxRepository extends JpaRepository<EmailOutbox, UUID> {

    // Lấy batch PENDING chưa vượt quá maxRetry — dùng LIMIT để tránh load quá nhiều
    @Query("""
            SELECT e FROM EmailOutbox e
            WHERE e.status = :status
            AND e.retryCount < :maxRetry
            ORDER BY e.createdAt ASC
            """)
    List<EmailOutbox> findPendingBatch(
            @Param("status") EmailStatus status,
            @Param("maxRetry") int maxRetry,
            Pageable pageable);
}