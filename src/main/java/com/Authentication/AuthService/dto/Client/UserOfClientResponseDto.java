package com.Authentication.AuthService.dto.client;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserOfClientResponseDto {
    private String userId;
    private String name;
    private String avatar;

    public void setUnknown() {
        this.userId = null;
        this.name = "unknown";
        this.avatar = null;
    }
}
