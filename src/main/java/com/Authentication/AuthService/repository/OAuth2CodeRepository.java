package com.Authentication.AuthService.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.Authentication.AuthService.entity.OAuth2Code;

public interface OAuth2CodeRepository extends JpaRepository<OAuth2Code, Long>{
    Optional<OAuth2Code> findByCode(String code);
}
