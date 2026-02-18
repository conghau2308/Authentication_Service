package com.Authentication.AuthService.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.Authentication.AuthService.entity.User;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
    /**
     * Tìm user theo username
     */
    Optional<User> findByUsername(String username);

    /**
     * Kiểm tra user có tồn tại theo username
     */
    boolean existsByUsername(String username);

    boolean existsByEmail(String email);
}
