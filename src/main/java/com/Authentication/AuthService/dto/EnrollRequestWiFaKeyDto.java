package com.Authentication.AuthService.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class EnrollRequestWiFaKeyDto {
    @JsonProperty("image_b64")
    private String imageB64;
}
