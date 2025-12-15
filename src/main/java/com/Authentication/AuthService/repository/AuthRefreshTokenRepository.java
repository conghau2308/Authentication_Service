package com.Authentication.AuthService.repository;

import com.Authentication.AuthService.entity.AuthRefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface AuthRefreshTokenRepository extends JpaRepository<AuthRefreshToken, Long> {
    
    Optional<AuthRefreshToken> findByToken(String token);
    
    Optional<AuthRefreshToken> findByUsername(String username);
    
    @Modifying
    @Transactional
    @Query("UPDATE AuthRefreshToken rt SET rt.revokedAt = :revokedAt WHERE rt.username = :username")
    void revokeAllByUsername(String username, LocalDateTime revokedAt);
    
    @Modifying
    @Transactional
    void deleteByUsername(String username);
    
    @Modifying
    @Transactional
    @Query("DELETE FROM AuthRefreshToken rt WHERE rt.expiresAt < :now OR rt.revokedAt IS NOT NULL")
    void deleteExpiredAndRevoked(LocalDateTime now);
}