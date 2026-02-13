package com.Authentication.AuthService.dto.OAuth;

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
public class AuthorizationCodeDto implements Serializable {
    private String code;

    // User đã đăng nhập
    private String username;

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

    // Đánh dấu code đã được dùng hay chưa (để chống tấn công replay)
    @Builder.Default
    private boolean used = false;
}
