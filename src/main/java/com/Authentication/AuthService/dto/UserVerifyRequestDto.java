package com.Authentication.AuthService.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserVerifyRequestDto {
    @NotBlank(message = "Username là bắt buộc.")
    private String username;

    @NotBlank(message = "Hash key là bắt buộc.")
    private String hash_k_b64;
}
