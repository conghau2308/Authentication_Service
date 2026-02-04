package com.Authentication.AuthService.services.oauth;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import com.Authentication.AuthService.dto.OAuth.UserInforResponseDto;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.exception.business.BusinessException;
import com.Authentication.AuthService.repository.UserRepository;
import com.Authentication.AuthService.services.auth.OAuthJwtService;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserInforService {
    private final OAuthJwtService oAuthJwtService;
    private final UserRepository userRepository;

    public UserInforResponseDto getUserInfo(String bearerToken) {
        String accessToken = extractBearerToken(bearerToken);
        Claims claims = oAuthJwtService.parseAndValidateAccessToken(accessToken);
        String username = claims.getSubject();

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new BusinessException("INVALID_TOKEN", "Không tìm thấy user từ Access Token."));
        return UserInforResponseDto.builder()
                .sub(user.getUsername())
                .email(user.getEmail())
                .name(user.getName())
                .user_id(user.getId().toString())
                .build();
    }

    private String extractBearerToken(String authorization) {
        if (!authorization.startsWith("Bearer "))
            throw new BusinessException("INVALID_TOKEN", "Authorization header không hợp lệ.", HttpStatus.UNAUTHORIZED);
        return authorization.substring(7);
    }
}
