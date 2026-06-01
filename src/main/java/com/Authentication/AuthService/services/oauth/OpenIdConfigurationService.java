package com.Authentication.AuthService.services.oauth;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.Authentication.AuthService.dto.jwks.OpenIdConfigurationDto;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class OpenIdConfigurationService {
    @Value("${jwt.issuer}")
    private String issuer;

    public OpenIdConfigurationDto getConfiguration() {
        return OpenIdConfigurationDto.builder()
                .issuer(issuer)
                .authorization_endpoint(issuer + "/oauth2/authorize/validate")
                .token_endpoint(issuer + "/oauth2/token")
                .userinfo_endpoint(issuer + "/oauth2/userinfo")
                .jwks_uri(issuer + "/.well-known/jwks.json")
                .end_session_endpoint(issuer + "/oauth2/logout")
                .response_types_supported(List.of("code"))
                .grant_types_supported(List.of("authorization_code", "refresh_token"))
                .subject_types_supported(List.of("public"))
                .id_token_signing_alg_values_supported(List.of("RSA256"))
                .token_endpoint_auth_methods_supported(List.of("client_secret_post"))
                .code_challenge_methods_supported(List.of("S256"))
                .scopes_supported(List.of("openid", "profile", "email"))
                .claims_supported(List.of("sub", "name", "email", "preferred_username", "user_id"))
                .build();
    }
}
