package com.Authentication.AuthService.services.enrollment;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

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
import com.Authentication.AuthService.dto.Client.UserOfClientResponseDto;
import com.Authentication.AuthService.entity.OAuth2Client;
import com.Authentication.AuthService.entity.OAuth2ClientMember;
import com.Authentication.AuthService.entity.OAuth2ClientSecret;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.enums.ClientType;
import com.Authentication.AuthService.exception.business.BusinessException;
import com.Authentication.AuthService.repository.OAuth2ClientSecretRepository;
import com.Authentication.AuthService.services.token.TokenCryptoService;
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
    private final TokenCryptoService tokenCryptoService;

    @Transactional
    public ClientEnrollResponseDto createClient(ClientEnrollRequestDto request, User user) {
        if (!StringUtils.hasText(request.getClientName())) {
            throw new BusinessException("INVALID_REQUEST", "Client name không được để trống.");
        }
        if (!StringUtils.hasText(request.getRedirectUri())) {
            throw new BusinessException("INVALID_REQUEST", "Redirect URI không được để trống.");
        }

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
                .createdBy(user)
                .build();
        oAuth2ClientRepository.save(client);

        return ClientEnrollResponseDto.builder()
                .clientId(client.getClientId())
                .clientName(client.getClientName())
                .redirectUri(client.getRedirectUri())
                .createdAt(client.getCreatedAt())
                .ownerName(user.getName())
                .build();
    }

    public List<ClientIdDto> getClientIdsByMemberUser(User user) {
        return oAuth2ClientMemberRepository.findClientIdDtosByUserId(user.getId());
    }

    public ClientCredentialsResponseDto getClientCredential(User user, String clientId) {
        OAuth2Client client = oAuth2ClientRepository.findByClientId(clientId);
        if (client == null) {
            throw new BusinessException("NOT_FOUND_CLIENT", "Không tìm thấy Client với Client ID.",
                    HttpStatus.NOT_FOUND);
        }
        validateClientOwnership(clientId, user.getId());
        // Step 1: Query secrets với createdBy
        List<OAuth2ClientSecret> secrets = clientSecretRepository
                .findByClientIdWithCreatedBy(clientId);

        // Step 2: Tìm secrets bị revoke
        List<UUID> revokedSecretIds = secrets.stream()
                .filter(s -> !s.isValid() && s.getRevokedBy() != null)
                .map(OAuth2ClientSecret::getId)
                .toList();

        // Step 3: Chỉ query revokedBy nếu có secrets bị revoke
        Map<UUID, User> revokedByMap = new HashMap<>();
        if (!revokedSecretIds.isEmpty()) {
            List<OAuth2ClientSecret> revokedSecrets = clientSecretRepository
                    .findRevokedByForSecrets(revokedSecretIds);

            revokedByMap = revokedSecrets.stream()
                    .collect(Collectors.toMap(
                            OAuth2ClientSecret::getId,
                            OAuth2ClientSecret::getRevokedBy));
        }

        // Step 4: Map to DTOs
        Map<UUID, User> finalRevokedByMap = revokedByMap;
        List<ClientSecretDto> secretDtos = secrets.stream()
                .map(secret -> mapToSecretDto(secret, finalRevokedByMap))
                .toList();

        return ClientCredentialsResponseDto.builder()
                .clientId(clientId)
                .clientSecrets(secretDtos)
                .build();
    }

    private ClientSecretDto mapToSecretDto(
            OAuth2ClientSecret secret,
            Map<UUID, User> revokedByMap) {

        ClientSecretDto dto = ClientSecretDto.builder()
                .secretId(secret.getId().toString())
                .maskedValue(secret.getSecretHint())
                .createdAt(secret.getCreatedAt())
                .createdByUser(buildUserInfor(secret.getCreatedBy()))
                .build();

        if (!secret.isValid()) {
            dto.setRevokedAt(secret.getRevokedAt());
            dto.setActive(false);

            // Lấy revokedBy từ map (đã được fetch riêng)
            User revokedBy = revokedByMap.get(secret.getId());
            dto.setRevokedByUser(revokedBy != null ? buildUserInfor(revokedBy) : null);
        }

        return dto;
    }

    private UserOfClientResponseDto buildUserInfor(User user) {
        if (user == null) {
            return null;
        }
        return UserOfClientResponseDto.builder()
                .userId(user.getId().toString())
                .name(user.getName())
                .avatar(null)
                .build();
    }

    @Transactional
    public ClientSecretResponseDto genNewClientSecrets(User user, String clientId) {
        validateNumberOfClientSecret(clientId);
        OAuth2Client client = oAuth2ClientRepository.findByClientId(clientId);
        if (client == null) {
            throw new BusinessException("NOT_FOUND_CLIENT", "Không tìm thấy Client với Client ID.",
                    HttpStatus.NOT_FOUND);
        }
        validateClientOwnership(clientId, user.getId());

        String rawSecret = tokenCryptoService.generateSecureRandomToken(32);
        String encodedSecret = passwordEncoder.encode(rawSecret);
        String secretHint = rawSecret.length() <= 8 ? rawSecret : "****" + rawSecret.substring(rawSecret.length() - 4);

        OAuth2ClientSecret clientSecret = OAuth2ClientSecret.builder()
                .client(client)
                .secretHash(encodedSecret)
                .secretHint(secretHint)
                .createdBy(user)
                .build();

        clientSecretRepository.save(clientSecret);

        return ClientSecretResponseDto.builder()
                .secretValue(rawSecret)
                .secretId(clientSecret.getId().toString())
                .createdByUsername(user.getUsername())
                .build();
    }

    @Transactional
    public void deleteClientSecret(User user, String clientId, UUID secretId) {
        validateClientOwnership(clientId, user.getId());

        OAuth2ClientSecret clientSecret = clientSecretRepository.findByIdAndClientClientId(secretId, clientId)
                .orElseThrow(() -> new BusinessException("NOT_FOUND_CLIENT_SECRET", "Không tìm thấy Client Secret.",
                        HttpStatus.NOT_FOUND));
        clientSecretRepository.delete(clientSecret);
    }

    // Revoke này nên mở rộng để có tính năng revoke tất cả token được exchange từ
    // secret này
    @Transactional
    public void revokeClientSecret(User user, String clientId, UUID secretId) {
        validateClientOwnership(clientId, user.getId());

        OAuth2ClientSecret clientSecret = clientSecretRepository.findByIdAndClientClientId(secretId, clientId)
                .orElseThrow(() -> new BusinessException("NOT_FOUND_CLIENT_SECRET", "Không tìm thấy Client Secret.",
                        HttpStatus.NOT_FOUND));

        if (!clientSecret.isValid()) {
            throw new BusinessException("INVALID_CLIENT_SECRET", "Client Secret đã bị thu hồi trước đó.",
                    HttpStatus.BAD_REQUEST);
        }
        clientSecret.revoke(user);

        clientSecretRepository.save(clientSecret);
    }

    private void validateClientOwnership(String clientId, UUID userId) {
        OAuth2ClientMember ownerShip = oAuth2ClientMemberRepository.findByClientIdAndUserIdIsActive(clientId, userId);
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
