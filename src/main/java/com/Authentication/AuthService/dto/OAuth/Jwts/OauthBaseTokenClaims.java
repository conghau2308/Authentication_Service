package com.Authentication.AuthService.dto.oauth.Jwts;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public abstract class OauthBaseTokenClaims {
    private String type;
    private String jti; // unique token id
}
