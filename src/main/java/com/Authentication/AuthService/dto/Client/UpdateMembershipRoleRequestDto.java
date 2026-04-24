package com.Authentication.AuthService.dto.client;

import java.util.UUID;

import com.Authentication.AuthService.enums.ClientRole;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class UpdateMembershipRoleRequestDto {
    @NotNull(message = "Id của thành viên là bắt buộc.")
    private UUID memberId;

    @NotNull(message = "Role không được để trống.")
    private ClientRole role;
}
