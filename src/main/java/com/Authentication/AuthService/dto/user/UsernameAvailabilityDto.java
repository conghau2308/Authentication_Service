package com.Authentication.AuthService.dto.user;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UsernameAvailabilityDto {
    private boolean available;
}
