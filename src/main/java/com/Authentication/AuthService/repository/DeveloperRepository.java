package com.Authentication.AuthService.repository;

import com.Authentication.AuthService.entity.Developer;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface DeveloperRepository extends JpaRepository<Developer, Long> {

    // Hàm này RẤT QUAN TRỌNG
    // Nó tìm developer bằng email (mà bạn gọi là username)
    Optional<Developer> findByEmail(String email); 
}