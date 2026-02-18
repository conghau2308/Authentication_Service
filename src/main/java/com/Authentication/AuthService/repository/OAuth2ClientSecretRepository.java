package com.Authentication.AuthService.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.Authentication.AuthService.entity.OAuth2ClientSecret;

import io.lettuce.core.dynamic.annotation.Param;

@Repository
public interface OAuth2ClientSecretRepository extends JpaRepository<OAuth2ClientSecret, UUID> {
    // Tìm tất cả secret theo clientId
    List<OAuth2ClientSecret> findByClientClientId(String clientId);

    Optional<OAuth2ClientSecret> findByIdAndClientClientId(UUID id, String clientId);

    List<OAuth2ClientSecret> findByClientClientIdAndIsActiveTrue(String clientId);

    @Query("""
            SELECT s FROM OAuth2ClientSecret s
            LEFT JOIN FETCH s.createdBy
            WHERE s.client.clientId = :clientId
            ORDER BY s.createdAt DESC
            """)
    List<OAuth2ClientSecret> findByClientIdWithCreatedBy(@Param("clientId") String clientId);

    // Query riêng lấy revokedBy cho secrets bị revoke
    @Query("""
            SELECT s FROM OAuth2ClientSecret s
            LEFT JOIN FETCH s.revokedBy
            WHERE s.id IN :secretIds AND s.revokedBy IS NOT NULL
            """)
    List<OAuth2ClientSecret> findRevokedByForSecrets(@Param("secretIds") List<UUID> secretIds);
}
