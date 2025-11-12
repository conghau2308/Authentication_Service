package com.Authentication.AuthService.services.auth;

import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class FaceAuthService {
    public boolean verifyUser(String username) {
        log.warn("Bỏ qua xác thực khuôn mặt");
        return true;
    }
}
