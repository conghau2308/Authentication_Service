package com.Authentication.AuthService.dto.client;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ClientEnrollRequestDto {
    @NotBlank(message = "Client Name không được để trống")
    private String clientName;

    @NotBlank(message = "Redirect Uri không được để trống")
    private String redirectUri;
}
