package com.Authentication.AuthService.dto.OAuth;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SSOStatusResponseDto {
    private boolean ssoAvailable;
    private String username;
    private boolean usernameMatch;
}
