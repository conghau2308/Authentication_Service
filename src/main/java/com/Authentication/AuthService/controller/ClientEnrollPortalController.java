package com.Authentication.AuthService.controller;

import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.Authentication.AuthService.dto.Client.ClientEnrollResponseDto;
import com.Authentication.AuthService.dto.Client.ClientCredentialsResponseDto;
import com.Authentication.AuthService.dto.Client.ClientEnrollRequestDto;
import com.Authentication.AuthService.dto.Client.ClientIdDto;
import com.Authentication.AuthService.dto.Client.ClientSecretResponseDto;
import com.Authentication.AuthService.dto.Response.ApiResponse;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.services.enrollment.ClientManagementService;

import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/client/developer")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Client Management", description = "Apis for managing clients")
public class ClientEnrollPortalController {
        private final ClientManagementService clientManagementService;

        @PostMapping("/enroll")
        public ResponseEntity<ApiResponse<ClientEnrollResponseDto>> registerNewClient(
                        @Valid @RequestBody ClientEnrollRequestDto request,
                        @AuthenticationPrincipal User user) {

                ClientEnrollResponseDto response = clientManagementService.createClient(request, user);

                return ResponseEntity.status(HttpStatus.CREATED)
                                .body(ApiResponse.success(response, "Client đã được đăng ký thành công."));
        }

        @PostMapping("/generate-secret")
        public ResponseEntity<ApiResponse<ClientSecretResponseDto>> generateNewClientSecret(
                        @AuthenticationPrincipal User user,
                        @PathVariable String clientId) {
                ClientSecretResponseDto response = clientManagementService.genNewClientSecrets(user, clientId);
                return ResponseEntity.ok(ApiResponse.success(response, "Tạo mới Client Secret thành công."));
        }

        @PostMapping("/revoke-secret")
        public ResponseEntity<ApiResponse<Void>> revokeClientSecret(
                        @AuthenticationPrincipal User user,
                        @PathVariable String clientId,
                        @PathVariable UUID secretId) {
                clientManagementService.revokeClientSecret(user, clientId, secretId);
                return ResponseEntity.ok(ApiResponse.success(null, "Thu hồi Client Secret thành công."));
        }

        @DeleteMapping("/delete-secret")
        public ResponseEntity<ApiResponse<Void>> deleteClientSecret(
                        @AuthenticationPrincipal User user,
                        @PathVariable String clientId,
                        @PathVariable UUID secretId) {
                clientManagementService.deleteClientSecret(user, clientId, secretId);
                return ResponseEntity.ok(ApiResponse.success(null, "Xóa Client Secret thành công."));
        }

        @GetMapping("/client-members")
        public ResponseEntity<ApiResponse<List<ClientIdDto>>> getClientMembers(
                        @AuthenticationPrincipal User user) {
                List<ClientIdDto> result = clientManagementService.getClientIdsByMemberUser(user);
                return ResponseEntity.ok(ApiResponse.success(result, "Lấy danh sách client thành công."));
        }

        @GetMapping("/credentials")
        public ResponseEntity<ApiResponse<ClientCredentialsResponseDto>> getClientCredential(
                        @AuthenticationPrincipal User user, @PathVariable String clientId) {
                ClientCredentialsResponseDto credentials = clientManagementService.getClientCredential(user, clientId);
                return ResponseEntity.ok(ApiResponse.success(credentials, "Lấy thông tin credentials thành công."));
        }
}