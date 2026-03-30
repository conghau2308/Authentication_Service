package com.Authentication.AuthService.dto.jwts;

import java.util.HashMap;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
public class RefreshTokenClaims extends BaseTokenClams {
    private String username;

    // Thêm tokenFamily nếu cần
    public Map<String, Object> toClaimsMap() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", getType());
        claims.put("jti", getJti());
        claims.put("username", username);
        return claims;
    }
}
