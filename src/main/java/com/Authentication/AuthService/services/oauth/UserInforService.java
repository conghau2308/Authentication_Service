package com.Authentication.AuthService.services.oauth;

import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import com.Authentication.AuthService.dto.OAuth.UserInforResponseDto;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.exception.business.BusinessException;
import com.Authentication.AuthService.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserInforService {
    private final UserRepository userRepository;
    private final AccessTokenService accessTokenService;

    public UserInforResponseDto getUserInfo(String bearerToken) {
        String accessToken = extractBearerToken(bearerToken);
        UUID userId = UUID.fromString(accessTokenService.getAccessToken(accessToken).getUserId());

        User user = userRepository.findById(userId)
                .orElseThrow(
                        () -> new BusinessException("INVALID_TOKEN", "Không tìm thấy user.", HttpStatus.UNAUTHORIZED));
        return UserInforResponseDto.builder()
                .email(user.getEmail())
                .name(user.getName())
                .user_id(user.getId().toString())
                .avatar(null)
                .build();
    }

    private String extractBearerToken(String authorization) {
        if (!authorization.startsWith("Bearer "))
            throw new BusinessException("INVALID_TOKEN", "Authorization header không hợp lệ.", HttpStatus.UNAUTHORIZED);
        return authorization.substring(7);
    }
}
