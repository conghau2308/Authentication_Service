package com.Authentication.AuthService.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.Authentication.AuthService.dto.ClientEnrollResponseDto;
import com.Authentication.AuthService.dto.CreateClientDto;
import com.Authentication.AuthService.dto.Client.ClientCredentialsResponseDto;
import com.Authentication.AuthService.dto.Client.ClientIdDto;
import com.Authentication.AuthService.dto.Client.ClientSecretResponseDto;
import com.Authentication.AuthService.dto.Response.ApiResponse;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.services.enrollment.ClientManagementService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/client/developer")
@RequiredArgsConstructor
@Slf4j
public class ClientEnrollPortalController {
        private static final String ACCESS_TOKEN_COOKIE = "ACCESS_TOKEN";

        private final ClientManagementService clientManagementService;

        @PostMapping("/enroll")
        public ResponseEntity<ApiResponse<ClientEnrollResponseDto>> registerNewClient(
                        @Valid @RequestBody CreateClientDto createClientDto,
                        @AuthenticationPrincipal User user) {

                // Có thể không cần check null do security sẽ check trước nếu có .authenticate()
                if (user == null) {
                        log.error("User is null");
                        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                        .body(ApiResponse.error("unauthorized", "Vui lòng đăng nhập lại."));
                }

                RegisteredClient clientWithRawSecret = clientManagementService.createClient(createClientDto, user);

                ClientEnrollResponseDto response = ClientEnrollResponseDto.builder()
                                .clientId(clientWithRawSecret.getClientId())
                                .clientSecret(clientWithRawSecret.getClientSecret())
                                .clientName(clientWithRawSecret.getClientName())
                                .owner(user.getUsername())
                                .build();

                return ResponseEntity.status(HttpStatus.CREATED)
                                .body(ApiResponse.success(response, "Client đã được đăng ký thành công."));
        }

        @PostMapping("/generate-secret")
        public ResponseEntity<ApiResponse<ClientSecretResponseDto>> generateNewClientSecret(
                        @CookieValue(name = ACCESS_TOKEN_COOKIE, required = false) String accessToken,
                        String clientId) {
                ClientSecretResponseDto response = clientManagementService.genNewClientSecrets(accessToken, clientId);
                return ResponseEntity.ok(ApiResponse.success(response, "Tạo mới Client Secret thành công."));
        }

        @PostMapping("/revoke-secret")
        public ResponseEntity<ApiResponse<Void>> revokeClientSecret(
                        @CookieValue(name = ACCESS_TOKEN_COOKIE, required = false) String accessToken,
                        String clientId,
                        String secretId) {
                clientManagementService.deleteClientSecret(accessToken, clientId, secretId);
                return ResponseEntity.ok(ApiResponse.success(null, "Thu hồi Client Secret thành công."));
        }

        @GetMapping("/client-members")
        public ResponseEntity<ApiResponse<List<ClientIdDto>>> getClientMembers(
                        @CookieValue(name = ACCESS_TOKEN_COOKIE, required = false) String accessToken) {
                List<ClientIdDto> result = clientManagementService.getClientIdsByMemberUsername(accessToken);
                return ResponseEntity.ok(ApiResponse.success(result, "Lấy danh sách client thành công."));
        }

        @GetMapping("/credentials")
        public ResponseEntity<ApiResponse<ClientCredentialsResponseDto>> getClientCredential(String clientId) {
                ClientCredentialsResponseDto credentials = clientManagementService.getClientCredential(clientId);
                return ResponseEntity.ok(ApiResponse.success(credentials, "Lấy thông tin credentials thành công."));
        }
}