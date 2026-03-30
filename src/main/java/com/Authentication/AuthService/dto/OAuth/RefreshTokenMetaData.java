package com.Authentication.AuthService.dto.oauth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RefreshTokenMetaData {
    private String tokenFamily;
    private int version;
    private long timestamp;
}
