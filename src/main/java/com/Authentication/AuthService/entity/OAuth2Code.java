package com.Authentication.AuthService.entity;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Builder;
import lombok.Data;

@Entity
@Table(name = "oauth2_authorization_codes")
@Data
@Builder
public class OAuth2Code {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long Id;

    // Chuỗi code ngẫu nhiên, là duy nhất
    @Column(nullable = false, unique = true)
    private String code;

    // User đã đăng nhập
    @Column(nullable = false)
    private String username;

    // Client đang yêu cầu
    @Column(nullable = false)
    private String clientId;

    // Thông tin context để xác thực tại /token endpoint
    private String redirectUri;
    private String scope;
    private String state;
    private String nonce;
    private String codeChallenge;
    private String codeChallengeMethod;

    // Thời điểm hết hạn (ví dụ: 5 phút)
    @Column(nullable = false)
    private Instant expiresAt;

    // Đánh dấu code đã được dùng hay chưa (để chống tấn công replay)
    private boolean used = false;
}
