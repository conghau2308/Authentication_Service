package com.Authentication.AuthService.dto.client;

import java.time.LocalDateTime;

import com.Authentication.AuthService.enums.ClientRole;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class ClientIdDto {
    private String clientId;
    private String clientName;
    private LocalDateTime createdAt;
    private ClientRole role;
}
