package com.Authentication.AuthService.dto.oauth.Jwts;

import java.util.HashMap;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
public class OauthIdTokenClaims extends OauthAccessTokenClaims {
    private String nonce;
    private Long auth_time;
    private String email;
    private String code_verifier;

    public Map<String, Object> toClaimsMap() {
        Map<String, Object> claims = super.toClaimsMap();
        if (nonce != null) claims.put("nonce", nonce);
        if (auth_time != null) claims.put("auth_time", auth_time);
        if (email != null) claims.put("email", email);
        if (code_verifier != null) claims.put("code_verifier", code_verifier);

        return claims;
    }
}
