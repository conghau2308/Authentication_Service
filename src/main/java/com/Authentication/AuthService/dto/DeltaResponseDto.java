package com.Authentication.AuthService.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Helper data (δ) trả về cho client để chạy WiFaKey verify cục bộ.
 * Không chứa key_hash — client chỉ cần δ và mask để reconstruct k.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeltaResponseDto {
    private String helper_data_b64;
    private String mask_b64;
}
