package com.Authentication.AuthService.dto.oauth;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class CheckSSORequestDto {
    private String clientID;
    private String redirectUri;
    private String username;
}
