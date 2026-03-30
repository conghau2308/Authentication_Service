package com.Authentication.AuthService.dto.oauth;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class FaceAuthRequestDto {
    @NotBlank
    private String username;
    @NotBlank
    private String image_b64;
    @NotBlank
    private String clientId;
    @NotBlank
    private String redirectUri;
    @NotBlank
    private String scope;
    @NotBlank
    private String state;
    @NotBlank
    private String nonce;
    @NotBlank
    private String codeChallenge;
    @NotBlank
    private String codeChallengeMethod;
}
