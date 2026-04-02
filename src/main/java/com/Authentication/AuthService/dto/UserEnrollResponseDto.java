package com.Authentication.AuthService.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserEnrollResponseDto {
    private String helper_data_b64;
    private String key_hash_b64;
}
