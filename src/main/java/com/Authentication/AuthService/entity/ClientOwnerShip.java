package com.Authentication.AuthService.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "client_ownership")
public class ClientOwnerShip {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long Id;

    @Column(nullable = false)
    private Long developerId;

    @Column(nullable = false, unique = true)
    private String clientId;

    protected ClientOwnerShip() {}

    public ClientOwnerShip(Long developerId, String clientId) {
        this.developerId = developerId;
        this.clientId = clientId;
    }

    public Long getDeveloperId() {
        return developerId;
    }
    public String getClientId() {
        return clientId;
    }

    public void setDeveloperId(Long developerId) {
        this.developerId = developerId;
    }
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }
}
