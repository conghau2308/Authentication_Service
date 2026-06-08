package com.Authentication.AuthService.services.auth;

import com.Authentication.AuthService.services.auth.wifakey.LdpcDecoderService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.util.Base64;

/**
 * WiFaKey verification — server-side decode architecture.
 *
 * Client chỉ gửi c' = b_selected XOR helper_data (noisy codeword); server tự
 * chạy LDPC decode (Neural-MS, ONNX), tái tạo khoá, hash và so sánh — client
 * không bao giờ thấy khoá tái tạo hay hash của nó.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class FaceAuthService {

    private final LdpcDecoderService ldpcDecoderService;

    /**
     * Giải mã c' từ client, tái tạo khoá, hash và so sánh với stored key_hash.
     * Dùng constant-time comparison để tránh timing attack.
     *
     * @param cPrimeB64        Base64 của c' (noisy codeword) client gửi lên
     * @param storedKeyHashB64 Base64 của hash(k) đã lưu khi enrollment
     * @return true nếu khớp
     */
    public boolean verifyCPrime(String cPrimeB64, String storedKeyHashB64) {
        if (cPrimeB64 == null || storedKeyHashB64 == null) {
            log.warn("verifyCPrime: null input");
            return false;
        }
        try {
            byte[] cPrime = Base64.getDecoder().decode(cPrimeB64);
            byte[] stored = Base64.getDecoder().decode(storedKeyHashB64);

            byte[] reconstructedHash = ldpcDecoderService.reconstructKeyHash(cPrime);
            boolean match = MessageDigest.isEqual(reconstructedHash, stored);
            log.info("WiFaKey verification: {}", match ? "✅ MATCH" : "❌ NO MATCH");
            return match;
        } catch (IllegalArgumentException e) {
            log.error("verifyCPrime: invalid Base64 input — {}", e.getMessage());
            return false;
        }
    }
}
