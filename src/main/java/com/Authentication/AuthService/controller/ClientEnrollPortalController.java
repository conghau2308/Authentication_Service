package com.Authentication.AuthService.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.Authentication.AuthService.dto.ClientSecretDto;
import com.Authentication.AuthService.dto.CreateClientDto;
import com.Authentication.AuthService.entity.Developer;
import com.Authentication.AuthService.services.enrollment.ClientManagementService;

@RestController
@RequestMapping("/portal/api/v1/enroll")
public class ClientEnrollPortalController {
    private final ClientManagementService clientService;

    public ClientEnrollPortalController(ClientManagementService clientService) {
        this.clientService = clientService;
    }

    @PostMapping
    public ResponseEntity<ClientSecretDto> registerNewClient(
            @RequestBody CreateClientDto createClientDto,
            @AuthenticationPrincipal Developer developer) {
        if(developer == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        RegisteredClient clientWithRawSecret = clientService.createClient(createClientDto, developer);

        ClientSecretDto responseDto = new ClientSecretDto(clientWithRawSecret.getClientId(), clientWithRawSecret.getClientSecret());

        return ResponseEntity.status(HttpStatus.CREATED).body(responseDto);
    }
}
