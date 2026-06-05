package com.Authentication.AuthService.dto.oauth;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IntrospectionResponseDto {

    /** Token còn active hay không (RFC 7662 required field) */
    private boolean active;

    /** User ID (subject) */
    private String sub;

    /** User ID (custom claim khớp với JWT payload của hệ thống) */
    @JsonProperty("user_id")
    private String userId;

    /** Username / preferred_username */
    private String username;

    /** Scope của token */
    private String scope;

    /** Client ID đã cấp token */
    @JsonProperty("client_id")
    private String clientId;

    /** Thời điểm hết hạn (Unix timestamp) */
    private Long exp;

    /** Thời điểm cấp phát (Unix timestamp) */
    private Long iat;

    /** Loại token */
    @JsonProperty("token_type")
    private String tokenType;
}
