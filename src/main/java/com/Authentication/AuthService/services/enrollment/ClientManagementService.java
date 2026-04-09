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

import com.Authentication.AuthService.dto.client.ClientCredentialsResponseDto;
import com.Authentication.AuthService.dto.client.ClientEnrollRequestDto;
import com.Authentication.AuthService.dto.client.ClientEnrollResponseDto;
import com.Authentication.AuthService.dto.client.ClientIdDto;
import com.Authentication.AuthService.dto.client.ClientSecretDto;
import com.Authentication.AuthService.dto.client.ClientSecretResponseDto;
import com.Authentication.AuthService.dto.client.MemberOfClientDto;
import com.Authentication.AuthService.dto.client.UpdateClientRequestDto;
import com.Authentication.AuthService.dto.client.UserOfClientResponseDto;
import com.Authentication.AuthService.entity.OAuth2Client;
import com.Authentication.AuthService.entity.OAuth2ClientMember;
import com.Authentication.AuthService.entity.OAuth2ClientSecret;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.enums.ClientPermission;
import com.Authentication.AuthService.enums.ClientRole;
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

                OAuth2ClientMember ownerShip = OAuth2ClientMember.builder()
                                .client(client)
                                .user(user)
                                .role(ClientRole.OWNER)
                                .build();
                oAuth2ClientMemberRepository.save(ownerShip);

                return ClientEnrollResponseDto.builder()
                                .id(client.getId())
                                .build();
        }

        @Transactional
        public void updateClient(User user, UUID client_id, UpdateClientRequestDto request) {
                OAuth2Client client = oAuth2ClientRepository.findById(client_id)
                                .orElseThrow(() -> new BusinessException("NOT_FOUND_CLIENT",
                                                "Không tìm thấy Client với Client ID.",
                                                HttpStatus.NOT_FOUND));

                validateClientOwnershipCanManageSetting(client.getId(), user.getId());

                // Do đang sử dụng PATCH nên Hibernate sẽ tự động check dirty nếu trường nào có
                // thay đổi thì mới cập nhật
                client.setClientName(request.getClientName());
                client.setRedirectUri(request.getRedirectUri());
        }

        @Transactional(readOnly = true)
        public List<ClientIdDto> getClientIdsByMemberUser(User user) {
                return oAuth2ClientMemberRepository.findClientIdDtosByUserId(user.getId());
        }

        @Transactional(readOnly = true)
        public List<MemberOfClientDto> getMembersByClientId(UUID clientId, User user) {
                validateClientOwnershipCanView(clientId, user.getId());
                return oAuth2ClientMemberRepository.findActiveMembersByClientId(clientId);
        }

        @Transactional(readOnly = true)
        public ClientCredentialsResponseDto getClientCredential(User user, UUID client_id) {
                OAuth2Client client = oAuth2ClientRepository.findById(client_id)
                                .orElseThrow(() -> new BusinessException("NOT_FOUND_CLIENT",
                                                "Không tìm thấy Client với Client ID.",
                                                HttpStatus.NOT_FOUND));

                OAuth2ClientMember ownerShip = validateClientOwnership(client.getId(), user.getId());
                // Step 1: Query secrets với createdBy
                List<OAuth2ClientSecret> secrets = clientSecretRepository.findByClient_idWithCreatedBy(client.getId());

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
                                .id(client.getId())
                                .clientId(client.getClientId())
                                .clientName(client.getClientName())
                                .redirectUri(client.getRedirectUri())
                                .clientIcon(null)
                                .clientHomePageUrl(null)
                                .createdAt(client.getCreatedAt())
                                .role(ownerShip.getRole())
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
        public ClientSecretResponseDto genNewClientSecrets(User user, UUID client_id) {
                validateNumberOfClientSecret(client_id);
                OAuth2Client client = oAuth2ClientRepository.findById(client_id)
                                .orElseThrow(() -> new BusinessException("NOT_FOUND_CLIENT",
                                                "Không tìm thấy Client với Client ID.",
                                                HttpStatus.NOT_FOUND));
                validateClientOwnership(client.getId(), user.getId());

                String rawSecret = tokenCryptoService.generateSecureRandomToken(32);
                String encodedSecret = passwordEncoder.encode(rawSecret);
                String secretHint = rawSecret.length() <= 8 ? rawSecret
                                : "****" + rawSecret.substring(rawSecret.length() - 4);

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
                                .build();
        }

        @Transactional
        public void deleteClientSecret(User user, UUID client_id, UUID secretId) {
                validateClientOwnership(client_id, user.getId());

                OAuth2ClientSecret clientSecret = clientSecretRepository
                                .findByIdAndClientId(secretId, client_id)
                                .orElseThrow(() -> new BusinessException("NOT_FOUND_CLIENT_SECRET",
                                                "Không tìm thấy Client Secret.",
                                                HttpStatus.NOT_FOUND));
                clientSecretRepository.delete(clientSecret);
        }

        // Revoke này nên mở rộng để có tính năng revoke tất cả token được exchange từ
        // secret này
        @Transactional
        public void revokeClientSecret(User user, UUID client_id, UUID secretId) {
                validateClientOwnership(client_id, user.getId());

                OAuth2ClientSecret clientSecret = clientSecretRepository
                                .findByIdAndClientId(secretId, client_id)
                                .orElseThrow(() -> new BusinessException("NOT_FOUND_CLIENT_SECRET",
                                                "Không tìm thấy Client Secret.",
                                                HttpStatus.NOT_FOUND));

                if (!clientSecret.isValid()) {
                        throw new BusinessException("INVALID_CLIENT_SECRET", "Client Secret đã bị thu hồi trước đó.",
                                        HttpStatus.BAD_REQUEST);
                }
                clientSecret.revoke(user);

                clientSecretRepository.save(clientSecret);
        }

        @Transactional
        public void deleteClient(User user, UUID client_id) {
                validateClientOwnershipCanDeleteClient(client_id, user.getId());
                if (!oAuth2ClientRepository.existsById(client_id)) {
                        throw new BusinessException(
                                        "NOT_FOUND_CLIENT",
                                        "Không tìm thấy client.",
                                        HttpStatus.NOT_FOUND);
                }
                oAuth2ClientRepository.deleteById(client_id);
        }

        private OAuth2ClientMember validateClientOwnership(UUID client_id, UUID userId) {
                OAuth2ClientMember ownerShip = oAuth2ClientMemberRepository.findByClientIdAndUserIdIsActive(client_id,
                                userId);
                if (ownerShip == null) {
                        throw new BusinessException("FORBIDDEN", "Bạn không có quyền truy cập vào Client này.",
                                        HttpStatus.FORBIDDEN);
                }

                if (!ownerShip.getRole().canManageSecrets()) {
                        throw new BusinessException("FORBIDDEN", "Bạn không có quyền quản lý secret của Client này.",
                                        HttpStatus.FORBIDDEN);
                }

                return ownerShip;
        }

        private void validateClientOwnershipCanManageSetting(UUID client_id, UUID userId) {
                OAuth2ClientMember ownerShip = oAuth2ClientMemberRepository.findByClientIdAndUserIdIsActive(client_id,
                                userId);
                if (ownerShip == null) {
                        throw new BusinessException("FORBIDDEN", "Bạn không có quyền truy cập vào Client này.",
                                        HttpStatus.FORBIDDEN);
                }

                if (!ownerShip.getRole().hasPermission(ClientPermission.MANAGE_SETTINGS)) {
                        throw new BusinessException("FORBIDDEN", "Bạn không có quyền quản lý cài đặt của Client này.",
                                        HttpStatus.FORBIDDEN);
                }
        }

        private void validateClientOwnershipCanDeleteClient(UUID client_id, UUID userId) {
                OAuth2ClientMember ownerShip = oAuth2ClientMemberRepository.findByClientIdAndUserIdIsActive(client_id,
                                userId);
                if (ownerShip == null) {
                        throw new BusinessException("FORBIDDEN", "Bạn không có quyền truy cập vào Client này.",
                                        HttpStatus.FORBIDDEN);
                }

                if (!ownerShip.getRole().hasPermission(ClientPermission.DELETE_CLIENT)) {
                        throw new BusinessException("FORBIDDEN", "Bạn không có quyền xóa Client này.",
                                        HttpStatus.FORBIDDEN);
                }
        }

        private void validateClientOwnershipCanView(UUID clientId, UUID userId) {
                OAuth2ClientMember ownerShip = oAuth2ClientMemberRepository.findByClientIdAndUserIdIsActive(clientId,
                                userId);
                if (ownerShip == null) {
                        throw new BusinessException("FORBIDDEN", "Bạn không có quyền truy cập vào Client này.",
                                        HttpStatus.FORBIDDEN);
                }

                if (!ownerShip.getRole().hasPermission(ClientPermission.VIEW)) {
                        throw new BusinessException("FORBIDDEN",
                                        "Bạn không có quyền xem danh sách thành viên của Client này.",
                                        HttpStatus.FORBIDDEN);
                }
        }

        private void validateNumberOfClientSecret(UUID client_id) {
                List<OAuth2ClientSecret> existingSecrets = clientSecretRepository
                                .findByClientIdAndIsActiveTrue(client_id);
                if (existingSecrets.size() >= 2) {
                        throw new BusinessException("LIMIT_EXCEEDED", "Đã đạt đến giới hạn số lượng Client Secret.",
                                        HttpStatus.BAD_REQUEST);
                }
        }
}
