package com.Authentication.AuthService.dto.client;

import java.time.LocalDateTime;
import java.util.UUID;

import com.Authentication.AuthService.enums.ClientRole;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class MemberOfClientDto {
    private UUID userId;
    private String name;
    private String email;
    // private String avatar;
    private ClientRole role;
    private LocalDateTime addedAt;
}
