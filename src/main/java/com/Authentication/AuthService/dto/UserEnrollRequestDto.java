package com.Authentication.AuthService.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserEnrollRequestDto {

    @NotBlank(message = "Username không được để trống")
    private String username;

    @NotBlank(message = "Tên không được để trống")
    private String name;

    @NotBlank(message = "Email không được để trống")
    @Email(message = "Email không hợp lệ")
    private String email;

    @NotBlank(message = "Helper data không được để trống")
    private String helper_data_b64;

    @NotBlank(message = "Mask không được để trống")
    private String mask_b64;

    @NotBlank(message = "Key hash không được để trống")
    private String key_hash_b64;
}