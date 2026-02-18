package com.Authentication.AuthService.dto.OAuth.Jwts;

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
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", getType());
        claims.put("jti", getJti());
        claims.put("nonce", nonce);
        claims.put("auth_time", auth_time);
        claims.put("email", email);
        claims.put("code_verifier", code_verifier);

        return claims;
    }
}
