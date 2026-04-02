package com.Authentication.AuthService.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.Authentication.AuthService.entity.OAuth2UserConsent;

@Repository
public interface OAuth2UserConsentRepository extends JpaRepository<OAuth2UserConsent, UUID> {
    Optional<OAuth2UserConsent> findByUserIdAndClientId(UUID userId, UUID clientId);

    boolean existsByUserIdAndClientId(UUID userId, UUID clientId);
}
