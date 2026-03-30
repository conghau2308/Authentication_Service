package com.Authentication.AuthService.dto.oauth.Jwts;

import java.util.HashMap;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

@Getter
@SuperBuilder
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class OauthAccessTokenClaims extends OauthBaseTokenClaims {
    private String client_id;
    private String scope;
    private String user_id;

    public Map<String, Object> toClaimsMap() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", getType());
        claims.put("jti", getJti());
        claims.put("client_id", client_id);
        claims.put("scope", scope);
        claims.put("user_id", user_id);
        return claims;
    }
}
