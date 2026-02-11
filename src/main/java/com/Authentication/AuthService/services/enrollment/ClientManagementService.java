package com.Authentication.AuthService.services.enrollment;

import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import com.Authentication.AuthService.dto.Client.ClientCredentialsResponseDto;
import com.Authentication.AuthService.dto.Client.ClientEnrollRequestDto;
import com.Authentication.AuthService.dto.Client.ClientEnrollResponseDto;
import com.Authentication.AuthService.dto.Client.ClientIdDto;
import com.Authentication.AuthService.dto.Client.ClientSecretDto;
import com.Authentication.AuthService.dto.Client.ClientSecretResponseDto;
import com.Authentication.AuthService.entity.OAuth2Client;
import com.Authentication.AuthService.entity.OAuth2ClientMember;
import com.Authentication.AuthService.entity.OAuth2ClientSecret;
import com.Authentication.AuthService.enums.ClientType;
import com.Authentication.AuthService.exception.business.BusinessException;
import com.Authentication.AuthService.repository.OAuth2ClientSecretRepository;
import com.Authentication.AuthService.services.auth.AuthJwtService;
import com.Authentication.AuthService.repository.OAuth2ClientMemberRepository;
import com.Authentication.AuthService.repository.OAuth2ClientRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class ClientManagementService {
    private final PasswordEncoder passwordEncoder;
    private final OAuth2ClientSecretRepository clientSecretRepository;
    private final OAuth2ClientMemberRepository oAuth2ClientMemberRepository;
    private final OAuth2ClientRepository oAuth2ClientRepository;
    private final AuthJwtService authJwtService;

    @Transactional
    public ClientEnrollResponseDto createClient(ClientEnrollRequestDto request, String accessToken) {
        if (!StringUtils.hasText(request.getClientName())) {
            throw new BusinessException("INVALID_REQUEST", "Client name không được để trống.");
        }
        if (!StringUtils.hasText(request.getRedirectUri())) {
            throw new BusinessException("INVALID_REQUEST", "Redirect URI không được để trống.");
        }

        String username = authJwtService.extractUsername(accessToken);
        String clientId = UUID.randomUUID().toString() + ".wifakey";
        String scopes = String.join("+", OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL);
        String grantTypes = String.join("+",
                AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
                AuthorizationGrantType.REFRESH_TOKEN.getValue());
        OAuth2Client client = OAuth2Client.builder()
                .clientId(clientId)
                .clientName(request.getClientName())
                .redirectUri(request.getRedirectUri())
                .clientType(ClientType.CONFIDENTIAL)
                .scopes(scopes)
                .grantTypes(grantTypes)
                .createdBy(username)
                .build();
        oAuth2ClientRepository.save(client);

        return ClientEnrollResponseDto.builder()
                .clientId(client.getClientId())
                .clientName(client.getClientName())
                .redirectUri(client.getRedirectUri())
                .createdAt(client.getCreatedAt())
                .ownerUsername(username)
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

    // Revoke này nên mở rộng để có tính năng revoke tất cả token được exchange từ
    // secret này
    @Transactional
    public void revokeClientSecret(String accessToken, String clientId, String secretId) {
        String username = authJwtService.extractUsername(accessToken);
        validateClientOwnership(clientId, username);

        OAuth2ClientSecret clientSecret = clientSecretRepository.findBySecretIdAndClientClientId(secretId, clientId)
                .orElseThrow(() -> new BusinessException("NOT_FOUND_CLIENT_SECRET", "Không tìm thấy Client Secret.",
                        HttpStatus.NOT_FOUND));

        if (!clientSecret.isValid()) {
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
