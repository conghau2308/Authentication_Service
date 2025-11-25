package com.Authentication.AuthService.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class FaceAuthLoginRequestDto {
    private String username;
    private String clientId;
    private String redirectUri;
    private String scope;
    private String state;
    private String nonce;
    private String codeChallenge;
    private String codeChallengeMethod;
}
