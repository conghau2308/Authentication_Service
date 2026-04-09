package com.Authentication.AuthService.dto.invitation;

import java.util.UUID;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AcceptInvitationResponseDto {
    private UUID clientId;
}