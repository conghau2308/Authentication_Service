package com.Authentication.AuthService.dto;

@lombok.Data
@lombok.NoArgsConstructor
@lombok.AllArgsConstructor
public class UserEnrollResponseDto {
    private String helper_data_b64;
    private String key_hash_b64;
}
