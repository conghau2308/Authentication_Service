package com.Authentication.AuthService.dto.user;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdateUserInforRequestDto {
    @NotBlank(message = "Tên không được để trống.")
    private String name;
}
