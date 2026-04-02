package com.Authentication.AuthService.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class OAuth2ValidateClientResponseDto {
    private String clientName;
    private String clientIcon;
    private String clientHomepageUrl;
    private String[] scopes;
}
