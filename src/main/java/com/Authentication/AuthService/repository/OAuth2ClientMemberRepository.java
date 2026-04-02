package com.Authentication.AuthService.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.Authentication.AuthService.dto.client.ClientIdDto;
import com.Authentication.AuthService.entity.OAuth2ClientMember;

@Repository
public interface OAuth2ClientMemberRepository extends JpaRepository<OAuth2ClientMember, Long> {
    // Tìm tất cả clientId theo userId => Bao gồm cả vai trò owner và member
    // Để tránh N + 1 query sử dụng join danh sách clientid với bảng clients
    // Và sử dụng dto để ít tồn ram nhất
    @Query("""
            SELECT new com.Authentication.AuthService.dto.client.ClientIdDto(cm.client.clientId, cm.client.clientName, cm.client.createdAt, cm.role)
            FROM OAuth2ClientMember cm
            WHERE cm.id = :id
            """)
    List<ClientIdDto> findClientIdDtosByUserId(UUID id);

    @Query("""
            SELECT cm
            FROM OAuth2ClientMember cm
            WHERE cm.client.clientId = :clientId AND cm.user.username = :username
            """)
    OAuth2ClientMember findByClientIdAndUsername(String clientId, String username);

    @Query("""
            SELECT cm
            FROM OAuth2ClientMember cm
            WHERE cm.client.clientId = :clientId AND cm.user.id = :userId AND cm.isActive = true
            """)
    OAuth2ClientMember findByClientIdAndUserIdIsActive(String clientId, UUID userId);
}
