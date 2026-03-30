package com.Authentication.AuthService.dto.jwks;

import java.util.List;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class JwksResponseDto {
    private List<JwksDto> keys;
}
