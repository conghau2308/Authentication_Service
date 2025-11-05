package com.Authentication.AuthService.repository;

import com.Authentication.AuthService.entity.Developer;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface DeveloperRepository extends JpaRepository<Developer, Long> {

    // tạm dùng username như email
    Optional<Developer> findByEmail(String email); 
}