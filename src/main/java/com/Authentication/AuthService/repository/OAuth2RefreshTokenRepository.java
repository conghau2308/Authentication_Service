package com.Authentication.AuthService.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.Authentication.AuthService.entity.OAuth2RefreshToken;

@Repository
public interface OAuth2RefreshTokenRepository extends JpaRepository<OAuth2RefreshToken, Long> {

    Optional<OAuth2RefreshToken> findByRefreshToken(String refreshToken);

    List<OAuth2RefreshToken> findByUsernameAndClientIdAndRevokedFalse(
            String username, String clientId);

    List<OAuth2RefreshToken> findByUsernameAndRevokedFalse(String username);

    /**
     * Tìm refresh token chưa hết hạn, chưa revoke, khớp client_id
     */
    @Query("SELECT rt FROM OAuth2RefreshToken rt " +
            "WHERE rt.refreshToken = :refreshToken " +
            "AND rt.clientId = :clientId " +
            "AND rt.revoked = false " +
            "AND rt.expiresAt > CURRENT_TIMESTAMP")
    Optional<OAuth2RefreshToken> findValidToken(
            @Param("refreshToken") String refreshToken,
            @Param("clientId") String clientId);
}