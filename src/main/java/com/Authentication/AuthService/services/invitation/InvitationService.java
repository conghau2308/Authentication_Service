package com.Authentication.AuthService.services.invitation;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.Authentication.AuthService.dto.invitation.AcceptInvitationResponseDto;
import com.Authentication.AuthService.dto.invitation.InvitationPreviewDto;
import com.Authentication.AuthService.dto.invitation.PendingInvitationDto;
import com.Authentication.AuthService.dto.invitation.SendInvitationRequestDto;
import com.Authentication.AuthService.entity.ClientInvitation;
import com.Authentication.AuthService.entity.OAuth2Client;
import com.Authentication.AuthService.entity.OAuth2ClientMember;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.enums.ClientPermission;
import com.Authentication.AuthService.enums.ClientRole;
import com.Authentication.AuthService.enums.InvitationStatus;
import com.Authentication.AuthService.exception.business.BusinessException;
import com.Authentication.AuthService.repository.ClientInvitationRepository;
import com.Authentication.AuthService.repository.OAuth2ClientMemberRepository;
import com.Authentication.AuthService.repository.OAuth2ClientRepository;
import com.Authentication.AuthService.repository.UserRepository;
import com.Authentication.AuthService.services.email.EmailOutboxService;
import com.Authentication.AuthService.services.token.TokenCryptoService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class InvitationService {

        private final ClientInvitationRepository invitationRepository;
        private final OAuth2ClientRepository clientRepository;
        private final OAuth2ClientMemberRepository memberRepository;
        private final UserRepository userRepository;
        private final EmailOutboxService emailOutboxService; // ← đổi từ EmailService
        private final TokenCryptoService tokenCryptoService;

        @Value("${app.invitation.expiry-days:7}")
        private int invitationExpiryDays;

        @Value("${app.base-url}")
        private String baseUrl;

        // ── Gửi invitation ────────────────────────────────────────────

        @Transactional
        public void sendInvitation(UUID clientId, User inviter, SendInvitationRequestDto request) {
                validatePermission(clientId, inviter.getId(), ClientPermission.MANAGE_MEMBERS);

                if (request.getRole() == ClientRole.OWNER) {
                        throw new BusinessException("INVALID_ROLE",
                                        "Không thể mời thành viên với role OWNER.", HttpStatus.BAD_REQUEST);
                }

                OAuth2Client client = clientRepository.findById(clientId)
                                .orElseThrow(() -> new BusinessException("NOT_FOUND_CLIENT",
                                                "Không tìm thấy Client.", HttpStatus.NOT_FOUND));

                User invitee = userRepository.findById(request.getUserId())
                                .orElseThrow(() -> new BusinessException("USER_NOT_FOUND",
                                                "Không tìm thấy người dùng này trong hệ thống.",
                                                HttpStatus.NOT_FOUND));

                if (invitee.getId().equals(inviter.getId())) {
                        throw new BusinessException("INVALID_INVITATION",
                                        "Bạn không thể tự mời bản thân.", HttpStatus.BAD_REQUEST);
                }

                boolean alreadyMember = memberRepository
                                .existsByClientIdAndUserIdAndIsActiveTrue(clientId, invitee.getId());
                if (alreadyMember) {
                        throw new BusinessException("ALREADY_MEMBER",
                                        "Người dùng này đã là thành viên của ứng dụng.", HttpStatus.CONFLICT);
                }

                boolean hasPending = invitationRepository
                                .existsByClientIdAndInviteeEmailAndStatus(
                                                clientId, invitee.getEmail(), InvitationStatus.PENDING);
                if (hasPending) {
                        throw new BusinessException("INVITATION_ALREADY_SENT",
                                        "Đã có lời mời đang chờ xác nhận cho email này.", HttpStatus.CONFLICT);
                }

                String token = tokenCryptoService.generateSecureRandomToken(32);
                String previewUrl = baseUrl + "/invitations?token=" + token;

                ClientInvitation invitation = ClientInvitation.builder()
                                .client(client)
                                .invitedBy(inviter)
                                .inviteeEmail(invitee.getEmail())
                                .role(request.getRole())
                                .token(token)
                                .expiresAt(LocalDateTime.now().plusDays(invitationExpiryDays))
                                .build();

                invitationRepository.save(invitation);

                // Lưu vào outbox trong CÙNG transaction — atomic với invitation
                // Nếu enqueue fail → toàn bộ transaction rollback, không có invitation "mồ côi"
                emailOutboxService.enqueue(
                                "email/invitation",
                                invitee.getEmail(),
                                "Bạn được mời tham gia " + client.getClientName(),
                                Map.of(
                                                "clientName", client.getClientName(),
                                                "invitedBy", inviter.getName(),
                                                "role", request.getRole().name(),
                                                "previewUrl", previewUrl,
                                                "expiresAt", invitation.getExpiresAt().toString(),
                                                "expiryDays", invitationExpiryDays));

                log.info("Invitation queued for {} to client {} by {}",
                                invitee.getEmail(), clientId, inviter.getId());
        }

        // ── Preview invitation trước khi confirm ──────────────────────

        @Transactional(readOnly = true)
        public InvitationPreviewDto getInvitationPreview(String token) {
                return findValidInvitationAsDto(token);
        }

        // ── Invitee chấp nhận ─────────────────────────────────────────

        @Transactional
        public AcceptInvitationResponseDto acceptInvitation(String token, User currentUser) {
                ClientInvitation invitation = findValidInvitationEntity(token);

                if (!currentUser.getEmail().equalsIgnoreCase(invitation.getInviteeEmail())) {
                        throw new BusinessException("FORBIDDEN",
                                        "Bạn không có quyền xác nhận lời mời này.", HttpStatus.FORBIDDEN);
                }

                Optional<OAuth2ClientMember> existingMember = memberRepository
                                .findByClientIdAndUserId(invitation.getClient().getId(), currentUser.getId());

                if (existingMember.isPresent()) {
                        OAuth2ClientMember member = existingMember.get();

                        if (member.isActive()) {
                                throw new BusinessException("ALREADY_MEMBER",
                                                "Bạn đã là thành viên của ứng dụng này.", HttpStatus.CONFLICT);
                        }

                        // Re-activate revoked member
                        member.reActive(invitation.getRole(), currentUser);
                        memberRepository.save(member);

                } else {
                        OAuth2ClientMember membership = OAuth2ClientMember.builder()
                                        .client(invitation.getClient())
                                        .user(currentUser)
                                        .role(invitation.getRole())
                                        .build();
                        memberRepository.save(membership);
                }

                invitation.accept();

                log.info("Invitation accepted by {} for client {}",
                                currentUser.getId(), invitation.getClient().getId());

                return AcceptInvitationResponseDto.builder().clientId(invitation.getClient().getId()).build();
        }

        // ── Invitee từ chối ───────────────────────────────────────────

        @Transactional
        public void declineInvitation(String token, User currentUser) {
                ClientInvitation invitation = findValidInvitationEntity(token);

                if (!currentUser.getEmail().equalsIgnoreCase(invitation.getInviteeEmail())) {
                        throw new BusinessException("FORBIDDEN",
                                        "Bạn không có quyền từ chối lời mời này.", HttpStatus.FORBIDDEN);
                }

                invitation.decline();

                log.info("Invitation declined by {} for client {}",
                                currentUser.getId(), invitation.getClient().getId());
        }

        // ── OWNER/ADMIN thu hồi invitation ───────────────────────────

        @Transactional
        public void revokeInvitation(UUID clientId, UUID invitationId, User revoker) {
                validatePermission(clientId, revoker.getId(), ClientPermission.MANAGE_MEMBERS);

                ClientInvitation invitation = invitationRepository
                                .findByIdAndClientId(invitationId, clientId)
                                .orElseThrow(() -> new BusinessException("NOT_FOUND_INVITATION",
                                                "Không tìm thấy lời mời.", HttpStatus.NOT_FOUND));

                if (!invitation.isPending()) {
                        throw new BusinessException("INVALID_INVITATION_STATUS",
                                        "Chỉ có thể thu hồi lời mời đang ở trạng thái PENDING.",
                                        HttpStatus.BAD_REQUEST);
                }

                invitation.revoke();
        }

        // ── Lấy danh sách PENDING invitations ────────────────────────

        @Transactional(readOnly = true)
        public List<PendingInvitationDto> getPendingInvitations(UUID clientId, User requester) {
                validatePermission(clientId, requester.getId(), ClientPermission.MANAGE_MEMBERS);

                return invitationRepository.findPendingByClientId(clientId);
        }

        // ── Helpers ───────────────────────────────────────────────────
        private InvitationPreviewDto findValidInvitationAsDto(String token) {
                InvitationPreviewDto preview = invitationRepository.findPendingByToken(token)
                                .orElseThrow(() -> new BusinessException("INVALID_TOKEN",
                                                "Lời mời này đã được sử dụng hoặc đã bị thu hồi.",
                                                HttpStatus.NOT_FOUND));

                if (LocalDateTime.now().isAfter(preview.getExpiresAt())) {
                        invitationRepository.markExpiredByToken(token);
                        throw new BusinessException("INVITATION_EXPIRED",
                                        "Lời mời đã hết hạn. Vui lòng yêu cầu lời mời mới.", HttpStatus.GONE);
                }

                return preview;
        }

        // Dùng cho: acceptInvitation, declineInvitation (cần gọi mutation trên entity)
        private ClientInvitation findValidInvitationEntity(String token) {
                ClientInvitation invitation = invitationRepository.findPendingEntityByToken(token)
                                .orElseThrow(() -> new BusinessException("INVALID_TOKEN",
                                                "Lời mời này đã được sử dụng hoặc đã bị thu hồi.",
                                                HttpStatus.NOT_FOUND));

                if (invitation.isExpired()) {
                        invitation.markExpired(); // dirty check → Hibernate tự UPDATE
                        throw new BusinessException("INVITATION_EXPIRED",
                                        "Lời mời đã hết hạn. Vui lòng yêu cầu lời mời mới.", HttpStatus.GONE);
                }

                return invitation;
        }

        private void validatePermission(UUID clientId, UUID userId, ClientPermission permission) {
                OAuth2ClientMember member = memberRepository
                                .findByClientIdAndUserIdIsActive(clientId, userId);

                if (member == null) {
                        throw new BusinessException("FORBIDDEN",
                                        "Bạn không có quyền truy cập ứng dụng này.", HttpStatus.FORBIDDEN);
                }

                if (!member.getRole().hasPermission(permission)) {
                        throw new BusinessException("FORBIDDEN",
                                        "Bạn không có quyền thực hiện thao tác này.", HttpStatus.FORBIDDEN);
                }
        }
}