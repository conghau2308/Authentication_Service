package com.Authentication.AuthService.dto.Jwts;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public abstract class BaseTokenClams {
    private String type;
    private String jti; // unique token id
}
