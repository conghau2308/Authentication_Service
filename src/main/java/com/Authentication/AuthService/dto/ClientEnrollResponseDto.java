package com.Authentication.AuthService.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ClientEnrollResponseDto {
    private String clientId;
    private String clientSecret;
    private String clientName;
    private String owner;
}
