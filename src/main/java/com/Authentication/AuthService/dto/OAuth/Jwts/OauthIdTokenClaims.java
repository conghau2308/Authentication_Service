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
    private String preferred_username;

    public Map<String, Object> toClaimsMap() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", getType());
        claims.put("jti", getJti());
        claims.put("nonce", nonce);
        claims.put("auth_time", auth_time);
        claims.put("preferred_username", preferred_username);

        return claims;
    }
}
