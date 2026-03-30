package com.Authentication.AuthService.dto.oauth;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ValidateOAuthResponseDto {
    private String redirect_url;
    private boolean sso_used;
}
