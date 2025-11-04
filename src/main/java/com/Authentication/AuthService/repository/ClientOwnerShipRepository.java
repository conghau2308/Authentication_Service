package com.Authentication.AuthService.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.Authentication.AuthService.entity.ClientOwnerShip;

@Repository
public interface ClientOwnerShipRepository extends JpaRepository<ClientOwnerShip, Long> {
    Optional<ClientOwnerShip> findByClientId(String clientId);
}
