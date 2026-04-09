package com.Authentication.AuthService.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.Authentication.AuthService.dto.user.UserSearchResultDto;
import com.Authentication.AuthService.entity.User;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
    /**
     * Tìm user theo username
     */
    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String emmail);

    /**
     * Kiểm tra user có tồn tại theo username
     */
    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    // Search theo username prefix
    @Query("""
            SELECT new com.Authentication.AuthService.dto.user.UserSearchResultDto(
                    u.id, u.username, u.name, u.email
            )
            FROM User u
            WHERE u.isActive = true
              AND LOWER(u.username) LIKE LOWER(CONCAT(:prefix, '%'))
            ORDER BY u.username ASC
            LIMIT 10
            """)
    List<UserSearchResultDto> searchByUsernamePrefix(@Param("prefix") String prefix);

    // Search theo email prefix (sau khi có @)
    @Query("""
            SELECT new com.Authentication.AuthService.dto.user.UserSearchResultDto(
                    u.id, u.username, u.name, u.email
            )
            FROM User u
            WHERE u.isActive = true
              AND LOWER(u.email) LIKE LOWER(CONCAT(:prefix, '%'))
            ORDER BY u.email ASC
            LIMIT 10
            """)
    List<UserSearchResultDto> searchByEmailPrefix(@Param("prefix") String prefix);
}
