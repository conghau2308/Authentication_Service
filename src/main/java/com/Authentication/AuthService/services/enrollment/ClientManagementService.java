package com.Authentication.AuthService.services.enrollment;

import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
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
import com.Authentication.AuthService.dto.Client.ClientCredentialsResponseDto;
import com.Authentication.AuthService.dto.Client.ClientIdDto;
import com.Authentication.AuthService.dto.Client.ClientSecretDto;
import com.Authentication.AuthService.dto.Client.ClientSecretResponseDto;
import com.Authentication.AuthService.entity.ClientOwnerShip;
import com.Authentication.AuthService.entity.OAuth2Client;
import com.Authentication.AuthService.entity.OAuth2ClientMember;
import com.Authentication.AuthService.entity.OAuth2ClientSecret;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.exception.business.BusinessException;
import com.Authentication.AuthService.repository.ClientOwnerShipRepository;
import com.Authentication.AuthService.repository.OAuth2ClientSecretRepository;
import com.Authentication.AuthService.repository.UserRepository;
import com.Authentication.AuthService.services.auth.AuthJwtService;
import com.Authentication.AuthService.repository.OAuth2ClientMemberRepository;
import com.Authentication.AuthService.repository.OAuth2ClientRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class ClientManagementService {
    private final RegisteredClientRepository clientRepository;
    private final ClientOwnerShipRepository ownerShipRepository;
    private final PasswordEncoder passwordEncoder;
    private final OAuth2ClientSecretRepository clientSecretRepository;
    private final UserRepository userRepository;
    private final OAuth2ClientMemberRepository oAuth2ClientMemberRepository;
    private final OAuth2ClientRepository oAuth2ClientRepository;
    private final AuthJwtService authJwtService;

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

    public List<ClientIdDto> getClientIdsByMemberUsername(String accessToken) {
        String username = authJwtService.extractUsername(accessToken);
        return oAuth2ClientMemberRepository.findClientIdDtosByUsername(username);
    }

    public ClientCredentialsResponseDto getClientCredential(String clientId) {
        OAuth2Client client = oAuth2ClientRepository.findByClientId(clientId);
        if (client == null) {
            throw new BusinessException("NOT_FOUND_CLIENT", "Không tìm thấy Client với Client ID.",
                    HttpStatus.NOT_FOUND);
        }
        List<OAuth2ClientSecret> secret = clientSecretRepository.findByClientClientId(clientId);
        if (secret.isEmpty()) {
            return ClientCredentialsResponseDto.builder().clientId(clientId).clientSecrets(null).build();
        }
        List<ClientSecretDto> listSecret = secret.stream().map(s -> ClientSecretDto.builder()
                .secretId(s.getSecretId())
                .maskedValue(s.getSecretHint())
                .createdByUserName(s.getCreatedBy())
                .createAt(s.getCreatedAt())
                .isActive(s.isValid())
                .revokedByUserName(s.getRevokedBy())
                .build()).toList();
        return ClientCredentialsResponseDto.builder().clientId(clientId).clientSecrets(listSecret).build();
    }

    @Transactional
    public ClientSecretResponseDto genNewClientSecrets(String accessToken, String clientId) {
        validateNumberOfClientSecret(clientId);
        OAuth2Client client = oAuth2ClientRepository.findByClientId(clientId);
        if (client == null) {
            throw new BusinessException("NOT_FOUND_CLIENT", "Không tìm thấy Client với Client ID.",
                    HttpStatus.NOT_FOUND);
        }
        String username = authJwtService.extractUsername(accessToken);
        validateClientOwnership(clientId, username);

        String rawSecret = UUID.randomUUID().toString();
        String encodedSecret = passwordEncoder.encode(rawSecret);
        String secretHint = rawSecret.length() <= 8 ? rawSecret : "****" + rawSecret.substring(rawSecret.length() - 4);

        OAuth2ClientSecret clientSecret = OAuth2ClientSecret.builder()
                .secretId(UUID.randomUUID().toString())
                .client(client)
                .secretHash(encodedSecret)
                .secretHint(secretHint)
                .createdBy(username)
                .build();

        clientSecretRepository.save(clientSecret);

        return ClientSecretResponseDto.builder()
                .secretValue(rawSecret)
                .secretId(clientSecret.getSecretId())
                .createdByUsername(username)
                .build();
    }

    @Transactional
    public void deleteClientSecret(String accessToken, String clientId, String secretId) {
        String username = authJwtService.extractUsername(accessToken);
        validateClientOwnership(clientId, username);

        OAuth2ClientSecret clientSecret = clientSecretRepository.findBySecretIdAndClientClientId(secretId, clientId)
                .orElseThrow(() -> new BusinessException("NOT_FOUND_CLIENT_SECRET", "Không tìm thấy Client Secret.",
                        HttpStatus.NOT_FOUND));
        clientSecretRepository.delete(clientSecret);
        ;
    }

    // Revoke này nên mở rộng để có tính năng revoke tất cả token được exchange từ secret này
    @Transactional
    public void revokeClientSecret(String accessToken, String clientId, String secretId) {
        String username = authJwtService.extractUsername(accessToken);
        validateClientOwnership(clientId, username);

        OAuth2ClientSecret clientSecret = clientSecretRepository.findBySecretIdAndClientClientId(secretId, clientId)
                .orElseThrow(() -> new BusinessException("NOT_FOUND_CLIENT_SECRET", "Không tìm thấy Client Secret.",
                        HttpStatus.NOT_FOUND));

        if(!clientSecret.isValid()) {
            throw new BusinessException("INVALID_CLIENT_SECRET", "Client Secret đã bị thu hồi trước đó.",
                    HttpStatus.BAD_REQUEST);
        }
        clientSecret.revoke(username);

        clientSecretRepository.save(clientSecret);
    }

    private void validateClientOwnership(String clientId, String username) {
        OAuth2ClientMember ownerShip = oAuth2ClientMemberRepository.findByClientIdAndUsername(clientId, username);
        if (ownerShip == null) {
            throw new BusinessException("FORBIDDEN", "Bạn không có quyền truy cập vào Client này.",
                    HttpStatus.FORBIDDEN);
        }

        if (!ownerShip.getRole().canManageSecrets()) {
            throw new BusinessException("FORBIDDEN", "Bạn không có quyền quản lý secret của Client này.",
                    HttpStatus.FORBIDDEN);
        }
    }

    private void validateNumberOfClientSecret(String clientId) {
        List<OAuth2ClientSecret> existingSecrets = clientSecretRepository.findByClientClientIdAndIsActiveTrue(clientId);
        if (existingSecrets.size() >= 2) {
            throw new BusinessException("LIMIT_EXCEEDED", "Đã đạt đến giới hạn số lượng Client Secret.",
                    HttpStatus.BAD_REQUEST);
        }
    }
}
