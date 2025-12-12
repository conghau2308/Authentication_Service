package com.Authentication.AuthService.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

@lombok.Data
@lombok.NoArgsConstructor
@lombok.AllArgsConstructor
public class VerifyRequestDto {
    private String helper_data_b64;
    private String key_hash_b64;
    
    @JsonProperty("image_b64")
    private String imageBase64; // Base64 encoded image từ frontend
}
