package com.Authentication.AuthService.dto.jwks;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class JwksDto {
    private String kty;
    private String use;
    private String kid;
    private String alg;
    private String n;
    private String e;
}
