package com.Authentication.AuthService.services.auth;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.Authentication.AuthService.entity.OAuth2Code;
import com.Authentication.AuthService.repository.OAuth2CodeRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthorizationCodeService {
    private final OAuth2CodeRepository oAuth2CodeRepository;

    // Dùng để tạo chuỗi code ngẫu nhiên an toàn
    private static final SecureRandom secureRandom = new SecureRandom();
    // Dùng để encode code b64
    private static final Base64.Encoder base64Encoder = Base64.getEncoder().withoutPadding();

    @Value("${auth-code.code-expiration-second}")
    private int codeExpirationSecond;

    private OAuth2Code buildAuthorizationCode(String code, String clientId, String username, String redirectUri,
            String scope, String state, String nonce, String codeChallenge, String codeChallengeMethod) {
        return OAuth2Code.builder()
                .code(code)
                .clientId(clientId)
                .username(username)
                .redirectUri(redirectUri)
                .scope(scope)
                .state(state)
                .nonce(nonce)
                .codeChallenge(codeChallenge)
                .codeChallengeMethod(codeChallengeMethod)
                .used(false)
                .expiresAt(Instant.now().plusSeconds(codeExpirationSecond))
                .build();
    }

    public String generateAuthorizationCode(String clientId, String username, String redirectUri,
            String scope, String state, String nonce, String codeChallenge, String codeChallengeMethod) {
        String code = generateSecureCodeString();
        OAuth2Code authCode = buildAuthorizationCode(code, clientId, username, redirectUri, scope, state, nonce,
                codeChallenge, codeChallengeMethod);
        oAuth2CodeRepository.save(authCode);
        return code;
    }

    private String generateSecureCodeString() {
        byte[] randomBytes = new byte[32]; // 32 bytes = 256 bits
        secureRandom.nextBytes(randomBytes);
        return base64Encoder.encodeToString(randomBytes);
    }
}
