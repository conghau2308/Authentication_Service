package com.Authentication.AuthService.services.enrollment;

import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.Authentication.AuthService.dto.CreateClientDto;
import com.Authentication.AuthService.entity.ClientOwnerShip;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.repository.ClientOwnerShipRepository;


@Service
public class ClientManagementService {
    private final RegisteredClientRepository clientRepository;
    private final ClientOwnerShipRepository ownerShipRepository;
    private final PasswordEncoder passwordEncoder;

    public ClientManagementService(RegisteredClientRepository clientRepository,
                                    ClientOwnerShipRepository ownerShipRepository,
                                    PasswordEncoder passwordEncoder) {
        this.clientRepository = clientRepository;
        this.ownerShipRepository = ownerShipRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public RegisteredClient createClient(CreateClientDto dto, User developer) {
        String clientId = UUID.randomUUID().toString();
        String rawSecret = UUID.randomUUID().toString();
        String encodedSecret = passwordEncoder.encode(rawSecret);

        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(encodedSecret)
                .clientName(dto.getAppName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUris(uris -> uris.addAll(dto.getRedirectUris()))
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE) // Có thể thay đổi để chọn scope cần thiết
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .tokenSettings(TokenSettings.builder().build())
                .build();
        
        this.clientRepository.save(registeredClient);

        ClientOwnerShip ownerShip = new ClientOwnerShip(developer.getId(), clientId);
        this.ownerShipRepository.save(ownerShip);

        return RegisteredClient.from(registeredClient)
                    .clientSecret(rawSecret)
                    .build();
    }
}
