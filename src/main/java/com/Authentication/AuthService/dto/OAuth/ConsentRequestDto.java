package com.Authentication.AuthService.dto.oauth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class ConsentRequestDto {
    private String client_id;
    private String redirect_uri;
    private String scope;
    private String state;
    private String nonce;
    private String code_challenge;
    private String code_challenge_method;
}
