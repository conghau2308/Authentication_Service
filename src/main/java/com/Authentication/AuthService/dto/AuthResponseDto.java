package com.Authentication.AuthService.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponseDto {
    private boolean success;
    private String message;
    private String accessToken;
    private String tokenType;
    private Long expiresIn; // seconds
    private UserInfoDto user;
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserInfoDto {
        private String username;
        private String name;
        private String email;
    }
}