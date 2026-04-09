package com.Authentication.AuthService.enums;

public enum EmailStatus {
    PENDING, // Chờ gửi
    SENT, // Đã gửi thành công
    FAILED // Thất bại sau max retry
}