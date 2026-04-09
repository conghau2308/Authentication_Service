package com.Authentication.AuthService.controller;

import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.Authentication.AuthService.dto.client.ClientCredentialsResponseDto;
import com.Authentication.AuthService.dto.client.ClientEnrollRequestDto;
import com.Authentication.AuthService.dto.client.ClientEnrollResponseDto;
import com.Authentication.AuthService.dto.client.ClientIdDto;
import com.Authentication.AuthService.dto.client.ClientSecretResponseDto;
import com.Authentication.AuthService.dto.client.MemberOfClientDto;
import com.Authentication.AuthService.dto.client.UpdateClientRequestDto;
import com.Authentication.AuthService.dto.invitation.PendingInvitationDto;
import com.Authentication.AuthService.dto.invitation.SendInvitationRequestDto;
import com.Authentication.AuthService.dto.response.ApiResponse;
import com.Authentication.AuthService.dto.user.UserSearchResultDto;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.services.enrollment.ClientManagementService;
import com.Authentication.AuthService.services.invitation.InvitationService;
import com.Authentication.AuthService.services.user.UserManageService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/developer")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Client Management", description = "Apis for managing clients")
public class ClientEnrollPortalController {
        private final ClientManagementService clientManagementService;
        private final InvitationService invitationService;
        private final UserManageService userManageService;

        @PostMapping("/enroll")
        public ResponseEntity<ApiResponse<ClientEnrollResponseDto>> registerNewClient(
                        @Valid @RequestBody ClientEnrollRequestDto request,
                        @AuthenticationPrincipal User user) {
                ClientEnrollResponseDto result = clientManagementService.createClient(request, user);

                return ResponseEntity.status(HttpStatus.CREATED)
                                .body(ApiResponse.success(result, "Client đã được đăng ký thành công."));
        }

        @PatchMapping("/update/{client_id}")
        public ResponseEntity<ApiResponse<Void>> updateClient(
                        @AuthenticationPrincipal User user,
                        @PathVariable UUID client_id,
                        @Valid @RequestBody UpdateClientRequestDto requestDto) {
                clientManagementService.updateClient(user, client_id, requestDto);
                return ResponseEntity.ok(ApiResponse.success(null, "Cập nhật thông tin Client thành công."));
        }

        @DeleteMapping("/{client_id}")
        public ResponseEntity<ApiResponse<Void>> deleteClient(
                        @AuthenticationPrincipal User user,
                        @PathVariable UUID client_id) {
                clientManagementService.deleteClient(user, client_id);
                return ResponseEntity.ok(ApiResponse.success(null, "Xóa Client thành công."));
        }

        @PostMapping("/generate-secret/{client_id}")
        public ResponseEntity<ApiResponse<ClientSecretResponseDto>> generateNewClientSecret(
                        @AuthenticationPrincipal User user,
                        @PathVariable UUID client_id) {
                ClientSecretResponseDto response = clientManagementService.genNewClientSecrets(user, client_id);
                return ResponseEntity.ok(ApiResponse.success(response, "Tạo mới Client Secret thành công."));
        }

        @PostMapping("/{client_id}/secrets/{secretId}/revoke")
        public ResponseEntity<ApiResponse<Void>> revokeClientSecret(
                        @AuthenticationPrincipal User user,
                        @PathVariable UUID client_id,
                        @PathVariable UUID secretId) {
                clientManagementService.revokeClientSecret(user, client_id, secretId);
                return ResponseEntity.ok(ApiResponse.success(null, "Thu hồi Client Secret thành công."));
        }

        @DeleteMapping("/{client_id}/secrets/{secretId}")
        public ResponseEntity<ApiResponse<Void>> deleteClientSecret(
                        @AuthenticationPrincipal User user,
                        @PathVariable UUID client_id,
                        @PathVariable UUID secretId) {
                clientManagementService.deleteClientSecret(user, client_id, secretId);
                return ResponseEntity.ok(ApiResponse.success(null, "Xóa Client Secret thành công."));
        }

        @GetMapping("/client-members")
        public ResponseEntity<ApiResponse<List<ClientIdDto>>> getClientMembers(
                        @AuthenticationPrincipal User user) {
                List<ClientIdDto> result = clientManagementService.getClientIdsByMemberUser(user);
                return ResponseEntity.ok(ApiResponse.success(result, "Lấy danh sách client thành công."));
        }

        @GetMapping("/client-members/{client_id}")
        public ResponseEntity<ApiResponse<List<MemberOfClientDto>>> getMembersByClientId(
                        @AuthenticationPrincipal User user,
                        @PathVariable UUID client_id) {
                List<MemberOfClientDto> result = clientManagementService.getMembersByClientId(client_id, user);
                return ResponseEntity.ok(ApiResponse.success(result, "Lấy danh sách các thành viên thành công."));
        }

        @GetMapping("/credentials/{client_id}")
        public ResponseEntity<ApiResponse<ClientCredentialsResponseDto>> getClientCredential(
                        @AuthenticationPrincipal User user, @PathVariable UUID client_id) {
                ClientCredentialsResponseDto credentials = clientManagementService.getClientCredential(user, client_id);
                return ResponseEntity.ok(ApiResponse.success(credentials, "Lấy thông tin credentials thành công."));
        }

        @GetMapping("/search-users")
        public ResponseEntity<ApiResponse<List<UserSearchResultDto>>> searchUsers(
                        @RequestParam String query) {
                List<UserSearchResultDto> result = userManageService.searchUsers(query);
                return ResponseEntity.ok(ApiResponse.success(result, "Lấy danh sách user thành công."));
        }

        // ── OWNER/ADMIN: gửi invitation ───────────────────────────────

        @PostMapping("/{client_id}/invitations")
        @Operation(summary = "Gửi lời mời thành viên")
        public ResponseEntity<ApiResponse<Void>> sendInvitation(
                        @PathVariable UUID client_id,
                        @Valid @RequestBody SendInvitationRequestDto request,
                        @AuthenticationPrincipal User user) {

                invitationService.sendInvitation(client_id, user, request);
                return ResponseEntity.status(HttpStatus.CREATED)
                                .body(ApiResponse.success(null, "Lời mời đã được gửi thành công."));
        }

        // ── OWNER/ADMIN: xem danh sách pending invitations ───────────

        @GetMapping("/{client_id}/invitations")
        @Operation(summary = "Lấy danh sách lời mời đang chờ")
        public ResponseEntity<ApiResponse<List<PendingInvitationDto>>> getPendingInvitations(
                        @PathVariable UUID client_id,
                        @AuthenticationPrincipal User user) {

                List<PendingInvitationDto> result = invitationService.getPendingInvitations(client_id, user);
                return ResponseEntity.ok(ApiResponse.success(result, "Lấy danh sách lời mời thành công."));
        }

        // ── OWNER/ADMIN: thu hồi invitation đang pending ─────────────

        @DeleteMapping("/{client_id}/invitations/{invitation_id}")
        @Operation(summary = "Thu hồi lời mời")
        public ResponseEntity<ApiResponse<Void>> revokeInvitation(
                        @PathVariable UUID client_id,
                        @PathVariable UUID invitation_id,
                        @AuthenticationPrincipal User user) {

                invitationService.revokeInvitation(client_id, invitation_id, user);
                return ResponseEntity.ok(ApiResponse.success(null, "Thu hồi lời mời thành công."));
        }
}