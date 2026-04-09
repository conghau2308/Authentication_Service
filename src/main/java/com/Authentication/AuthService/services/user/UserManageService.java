package com.Authentication.AuthService.services.user;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.Authentication.AuthService.dto.PaginatedResponse;
import com.Authentication.AuthService.dto.user.AuthorizedApplicationDto;
import com.Authentication.AuthService.dto.user.AuthorizedApplicationResponseDto;
import com.Authentication.AuthService.dto.user.UpdateUserInforRequestDto;
import com.Authentication.AuthService.dto.user.UserSearchResultDto;
import com.Authentication.AuthService.entity.OAuth2UserConsent;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.exception.business.BusinessException;
import com.Authentication.AuthService.repository.OAuth2UserConsentRepository;
import com.Authentication.AuthService.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserManageService {
    private final UserRepository userRepository;
    private final OAuth2UserConsentRepository userConsentRepository;

    @Transactional
    public void updateUserInfor(User user, UpdateUserInforRequestDto requestDto) {
        user.setName(requestDto.getName());
        userRepository.save(user);
    }

    @Transactional(readOnly = true)
    public PaginatedResponse<AuthorizedApplicationResponseDto> getAuthorizedApplications(User user, int page,
            int size) {
        // Spring data tính từ 0 nên muốn truyền 1 thì trư 1 đơn vị
        Pageable pageable = PageRequest.of(page - 1, size, Sort.by("grantedAt").descending());
        Page<AuthorizedApplicationDto> result = userConsentRepository.findConsentsByUserId(user.getId(), pageable);

        List<AuthorizedApplicationResponseDto> items = result.getContent()
                .stream()
                .map(consent -> AuthorizedApplicationResponseDto.builder()
                        .id(consent.getId())
                        .grantedScopes(parseScopes(consent.getGrantedScopes()))
                        .grantedAt(consent.getGrantedAt())
                        .updatedAt(consent.getUpdatedAt())
                        .clientName(consent.getClientName())
                        .build())
                .toList();

        return PaginatedResponse.<AuthorizedApplicationResponseDto>builder()
                .items(items)
                .page(page)
                .size(size)
                .totalItems(result.getTotalElements())
                .totalPages(result.getTotalPages())
                .build();
    }

    private List<String> parseScopes(String scopes) {
        if (scopes == null || scopes.isBlank())
            return List.of();
        return Arrays.asList(scopes.split("[+ ]+")); // tách theo + hoặc khoảng trắng
    }

    @Transactional
    public void revokeApplicationConsent(User user, UUID consent_id) {
        if (!userConsentRepository.existsByIdAndUserId(consent_id, user.getId())) {
            throw new BusinessException("CONSENT_NOT_FOUND", "Không tìm thấy consent trên hệ thống.");
        }
        userConsentRepository.deleteById(consent_id);
    }

    @Transactional(readOnly = true)
    public List<UserSearchResultDto> searchUsers(String keyword) {
        String trimmed = keyword == null ? "" : keyword.trim();
        if (trimmed.length() < 2) {
            throw new BusinessException("INVALID_KEYWORD",
                    "Từ khóa tìm kiếm phải có ít nhất 2 ký tự.",
                    HttpStatus.BAD_REQUEST);
        }

        // Có @ → search email, không có → search username
        if (trimmed.contains("@")) {
            return userRepository.searchByEmailPrefix(trimmed);
        }
        return userRepository.searchByUsernamePrefix(trimmed);
    }
}
