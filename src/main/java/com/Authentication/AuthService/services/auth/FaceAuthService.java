package com.Authentication.AuthService.services.auth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.util.Base64;

/**
 * WiFaKey verification — client-side architecture.
 *
 * Server không xử lý ảnh hay embedding. Client tự chạy fuzzy commitment
 * và chỉ gửi hash_k lên. Service này chỉ so sánh hash.
 */
@Service
@Slf4j
public class FaceAuthService {

    /**
     * So sánh hash_k từ client với stored key_hash trong DB.
     * Dùng constant-time comparison để tránh timing attack.
     *
     * @param hashKB64       Base64 của hash(k) client gửi lên
     * @param storedKeyHashB64 Base64 của hash(k) đã lưu khi enrollment
     * @return true nếu khớp
     */
    public boolean verifyHashK(String hashKB64, String storedKeyHashB64) {
        if (hashKB64 == null || storedKeyHashB64 == null) {
            log.warn("verifyHashK: null input");
            return false;
        }
        try {
            byte[] received = Base64.getDecoder().decode(hashKB64);
            byte[] stored   = Base64.getDecoder().decode(storedKeyHashB64);
            boolean match   = MessageDigest.isEqual(received, stored);
            log.info("WiFaKey hash verification: {}", match ? "✅ MATCH" : "❌ NO MATCH");
            return match;
        } catch (IllegalArgumentException e) {
            log.error("verifyHashK: invalid Base64 input — {}", e.getMessage());
            return false;
        }
    }
}
