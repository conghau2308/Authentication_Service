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
public class OauthRefreshTokenClaims extends OauthBaseTokenClaims {
    private String client_id;
    // Thêm token family nếu cần

    public Map<String, Object> toClaimsMap() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", getType());
        claims.put("jti", getJti());
        claims.put("client_id", client_id);
        return claims;
    }
}
