package com.Authentication.AuthService.dto.oauth;

import java.util.List;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthorizeResponseDto {
    private String redirect_url; // null nếu cần consent
    private boolean consent_required;
    private List<String> pending_scopes; // scopes cần user đồng ý
    private String client_name;
}
