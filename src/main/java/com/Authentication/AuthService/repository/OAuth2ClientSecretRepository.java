package com.Authentication.AuthService.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.Authentication.AuthService.entity.OAuth2ClientSecret;

@Repository
public interface OAuth2ClientSecretRepository extends JpaRepository<OAuth2ClientSecret, String> {
    // Tìm tất cả secret theo clientId
    List<OAuth2ClientSecret> findByClientClientId(String clientId);

    Optional<OAuth2ClientSecret> findBySecretIdAndClientClientId(String secretId, String clientId);

    List<OAuth2ClientSecret> findByClientClientIdAndIsActiveTrue(String clientId);
}
