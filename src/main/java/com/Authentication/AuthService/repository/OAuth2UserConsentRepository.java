package com.Authentication.AuthService.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.Authentication.AuthService.dto.user.AuthorizedApplicationDto;
import com.Authentication.AuthService.entity.OAuth2UserConsent;

@Repository
public interface OAuth2UserConsentRepository extends JpaRepository<OAuth2UserConsent, UUID> {
    Optional<OAuth2UserConsent> findByUserIdAndClientId(UUID userId, UUID clientId);

    boolean existsByUserIdAndClientId(UUID userId, UUID clientId);

    boolean existsByIdAndUserId(UUID consentId, UUID userId);

    void deleteByUserIdAndClientId(UUID userId, UUID clientId);

    @Query("""
            SELECT new com.Authentication.AuthService.dto.user.AuthorizedApplicationDto(
                c.id,
                c.grantedScopes,
                c.grantedAt,
                c.updatedAt,
                c.client.clientName
            )
            FROM OAuth2UserConsent c
            WHERE c.user.id = :userId
            """)
    Page<AuthorizedApplicationDto> findConsentsByUserId(@Param("userId") UUID userId, Pageable pageable);
}
