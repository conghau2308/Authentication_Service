package com.Authentication.AuthService.enums;

public enum LimitStrategy {
    BY_IP, // theo IP → dùng cho endpoint thông thường
    BY_CLIENT_ID, // theo client_id → dùng cho OAuth endpoints
    BY_USER, // theo user_id → dùng cho endpoint sau khi authed
    BY_IP_AND_CLIENT_ID // kết hợp cả 2
}
