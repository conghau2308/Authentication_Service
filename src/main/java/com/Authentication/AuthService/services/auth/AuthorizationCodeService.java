package com.Authentication.AuthService.services.auth;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

import org.springframework.stereotype.Service;

import com.Authentication.AuthService.entity.OAuth2Code;
import com.Authentication.AuthService.repository.OAuth2CodeRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthorizationCodeService {
    private final OAuth2CodeRepository codeRepository;

    // Dùng để tạo chuỗi ngẫu nhiên an toàn
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();

    // Sét đặt thời gian hết hạn cho code (ví dụ: 5 phút)
    private static final long CODE_EXPIRATION_SECONDS = 300;

    /**
     * Tạo, lưu trữ và trả về một authorization_code mới.
     * 
     * @param clientId    Client ID
     * @param username    Tên người dùng đã xác thực
     * @param redirectUri Redirect URI để xác thực sau này
     * @param scope       Scope được yêu cầu
     * @return Chuỗi authorization_code
     */
    public String generateAuthorizationCode(String clientId, String username, String redirectUri, String scope) {

        // 1. Tạo một chuỗi ngẫu nhiên an toàn
        String code = generateSecureCodeString();

        // 2. Tạo đối tượng Entity để lưu
        OAuth2Code authCode = new OAuth2Code();
        authCode.setCode(code);
        authCode.setUsername(username);
        authCode.setClientId(clientId);
        authCode.setRedirectUri(redirectUri);
        authCode.setScope(scope);
        authCode.setExpiresAt(Instant.now().plusSeconds(CODE_EXPIRATION_SECONDS));
        authCode.setUsed(false);

        // 3. Lưu vào cơ sở dữ liệu
        codeRepository.save(authCode);

        log.info("Đã tạo và lưu trữ authorization_code cho user: {}", username);

        // 4. Trả về chuỗi code cho controller
        return code;
    }

    /**
     * Tạo một chuỗi 32-byte (256-bit) ngẫu nhiên, an toàn
     * và mã hóa nó thành Base64 URL-safe.
     */
    private String generateSecureCodeString() {
        byte[] randomBytes = new byte[32]; // 32 bytes = 256 bits
        secureRandom.nextBytes(randomBytes);
        return base64Encoder.encodeToString(randomBytes);
    }
}
