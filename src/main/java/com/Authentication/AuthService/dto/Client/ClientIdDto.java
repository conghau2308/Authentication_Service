package com.Authentication.AuthService.dto.Client;

import java.time.LocalDateTime;

import com.Authentication.AuthService.enums.ClientRole;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ClientIdDto {
    private String clientId;
    private String clientName;
    private LocalDateTime createdAt;
    private ClientRole role;
}
