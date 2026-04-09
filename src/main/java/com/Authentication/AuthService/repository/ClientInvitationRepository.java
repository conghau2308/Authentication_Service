package com.Authentication.AuthService.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.Authentication.AuthService.dto.invitation.InvitationPreviewDto;
import com.Authentication.AuthService.dto.invitation.PendingInvitationDto;
import com.Authentication.AuthService.entity.ClientInvitation;
import com.Authentication.AuthService.enums.InvitationStatus;

@Repository
public interface ClientInvitationRepository extends JpaRepository<ClientInvitation, UUID> {

        Optional<ClientInvitation> findByToken(String token);

        @Query("""
                        SELECT new com.Authentication.AuthService.dto.invitation.InvitationPreviewDto(
                            i.client.clientName,
                            i.role,
                            i.invitedBy.name,
                            i.invitedBy.email,
                            i.inviteeEmail,
                            i.expiresAt
                        )
                        FROM ClientInvitation i
                        WHERE i.token = :token
                          AND i.status = com.Authentication.AuthService.enums.InvitationStatus.PENDING
                        """)
        Optional<InvitationPreviewDto> findPendingByToken(@Param("token") String token);

        @Modifying
        @Query("""
                        UPDATE ClientInvitation i
                        SET i.status = com.Authentication.AuthService.enums.InvitationStatus.EXPIRED
                        WHERE i.token = :token
                        """)
        void markExpiredByToken(@Param("token") String token);

        // Query entity với JOIN FETCH để tránh lazy load client
        @Query("""
                        SELECT i FROM ClientInvitation i
                        JOIN FETCH i.client
                        WHERE i.token = :token
                          AND i.status = com.Authentication.AuthService.enums.InvitationStatus.PENDING
                        """)
        Optional<ClientInvitation> findPendingEntityByToken(@Param("token") String token);

        // Kiểm tra đã có PENDING invitation cho email này trong client chưa
        boolean existsByClientIdAndInviteeEmailAndStatus(
                        UUID clientId, String inviteeEmail, InvitationStatus status);

        // Lấy tất cả PENDING invitations của 1 client — hiển thị trên UI
        @Query("""
                        SELECT new com.Authentication.AuthService.dto.invitation.PendingInvitationDto(
                                i.id,
                                i.inviteeEmail,
                                i.role,
                                i.status,
                                i.expiresAt,
                                i.createdAt,
                                i.invitedBy.name
                        )
                        FROM ClientInvitation i
                        WHERE i.client.id = :clientId
                          AND i.status = 'PENDING'
                        ORDER BY i.createdAt DESC
                        """)
        List<PendingInvitationDto> findPendingByClientId(@Param("clientId") UUID clientId);

        // Bulk expire — dùng cho cron job, bulk update thay vì load từng entity
        @Modifying
        @Query("""
                        UPDATE ClientInvitation i
                        SET i.status = 'EXPIRED'
                        WHERE i.status = 'PENDING'
                        AND i.expiresAt < :now
                        """)
        int bulkExpireInvitations(@Param("now") LocalDateTime now);

        Optional<ClientInvitation> findByIdAndClientId(UUID id, UUID clientId);
}