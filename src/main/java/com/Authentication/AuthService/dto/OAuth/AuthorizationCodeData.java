package com.Authentication.AuthService.dto.oauth;

import java.io.Serializable;
import java.time.Instant;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthorizationCodeData implements Serializable {
    // User đã đăng nhập
    private String userId;

    // Client đang yêu cầu
    private String clientId;

    // Thông tin context để xác thực tại /token endpoint
    private String redirectUri;
    private String scope;
    private String state;
    private String nonce;
    private String codeChallenge;
    private String codeChallengeMethod;

    // Thời điểm hết hạn
    private Instant expiresAt;
}
