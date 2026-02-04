package com.Authentication.AuthService.dto.OAuth;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserInforResponseDto {
    private String sub;
    private String user_id;
    private String name;
    private String email;
}
