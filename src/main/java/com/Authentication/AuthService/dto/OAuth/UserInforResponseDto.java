package com.Authentication.AuthService.dto.oauth;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserInforResponseDto {
    private String user_id;
    private String name;
    private String email;
    private String avatar;
}
