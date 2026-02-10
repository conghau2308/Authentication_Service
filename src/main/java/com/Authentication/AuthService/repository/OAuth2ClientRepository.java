package com.Authentication.AuthService.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.Authentication.AuthService.entity.OAuth2Client;

public interface OAuth2ClientRepository extends JpaRepository<OAuth2Client, String> {
    OAuth2Client findByClientId(String clientId);
}
