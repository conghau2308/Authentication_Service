package com.Authentication.AuthService.dto.oauth;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthorizeRequestDto {
    private String client_id;
    private String redirect_uri;
    private String scope;
    private String state;
    private String nonce;
    private String code_challenge;
    private String code_challenge_method;
}
