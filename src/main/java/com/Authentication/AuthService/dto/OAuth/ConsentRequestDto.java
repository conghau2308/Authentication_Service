package com.Authentication.AuthService.dto.oauth;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ConsentRequestDto {
    private String client_id;
    private String redirect_uri;
    private String scope;
    private String state;
    private String nonce;
    private String code_challenge;
    private String code_challenge_method;
}
