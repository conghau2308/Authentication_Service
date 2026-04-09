package com.Authentication.AuthService.dto.user;

import java.util.UUID;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserSearchResultDto {
    private UUID userId;
    private String username;
    private String name;
    private String email;
}
