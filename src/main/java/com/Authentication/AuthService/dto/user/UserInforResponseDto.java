package com.Authentication.AuthService.dto.user;

import com.Authentication.AuthService.enums.UserRole;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserInforResponseDto {
    private String userId;
    private String name;
    private String email;
    private UserRole role;
    private boolean isActive;
}
