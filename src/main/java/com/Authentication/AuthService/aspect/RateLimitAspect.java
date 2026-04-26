package com.Authentication.AuthService.aspect;

import java.lang.reflect.Method;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.server.ResponseStatusException;

import com.Authentication.AuthService.annotation.RateLimit;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.enums.LimitStrategy;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Aspect
@Component
@Slf4j
@RequiredArgsConstructor
public class RateLimitAspect {

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    @Around("execution(* com.Authentication.AuthService.controller..*.*(..))")
    public Object around(ProceedingJoinPoint joinPoint) throws Throwable {

        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        RateLimit rateLimit = method.getAnnotation(RateLimit.class);
        if (rateLimit == null) {
            rateLimit = joinPoint.getTarget().getClass().getAnnotation(RateLimit.class);
        }

        int limit = (rateLimit != null) ? rateLimit.limit() : 50;
        int duration = (rateLimit != null) ? rateLimit.durationSeconds() : 60;
        LimitStrategy strategy = (rateLimit != null) ? rateLimit.strategy() : LimitStrategy.BY_IP;

        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes())
                .getRequest();

        // ✅ Tạo bucket key theo strategy
        String bucketKey = resolveBucketKey(request, strategy, joinPoint.getSignature().toShortString());

        if (bucketKey == null) {
            // Không resolve được key → cho đi tiếp
            return joinPoint.proceed();
        }

        Bucket bucket = buckets.computeIfAbsent(bucketKey, k -> Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(limit)
                        .refillGreedy(limit, Duration.ofSeconds(duration))
                        .build())
                .build());

        if (bucket.tryConsume(1)) {
            return joinPoint.proceed();
        }

        log.warn("Rate limit exceeded - strategy: {}, key: {}", strategy, bucketKey);
        throw new ResponseStatusException(
                HttpStatus.TOO_MANY_REQUESTS,
                "Quá nhiều request. Vui lòng thử lại sau.");
    }

    private String resolveBucketKey(HttpServletRequest request,
            LimitStrategy strategy,
            String methodKey) {
        String ip = getClientIp(request);

        return switch (strategy) {
            case BY_IP ->
                ip + ":" + methodKey;

            case BY_CLIENT_ID -> {
                // Lấy client_id từ request param hoặc body
                String clientId = extractClientId(request);
                yield clientId != null ? "client:" + clientId + ":" + methodKey : null;
            }

            case BY_USER -> {
                // Lấy từ SecurityContext sau khi đã authed
                String userId = extractUserId();
                yield userId != null ? "user:" + userId + ":" + methodKey : null;
            }

            case BY_IP_AND_CLIENT_ID -> {
                String clientId = extractClientId(request);
                yield clientId != null ? ip + ":client:" + clientId + ":" + methodKey : null;
            }
        };
    }

    private String extractClientId(HttpServletRequest request) {
        // Lấy từ query param: /oauth/token?client_id=xxx
        String clientId = request.getParameter("client_id");
        if (clientId != null)
            return clientId;

        // Lấy từ Basic Auth header: Authorization: Basic
        // base64(client_id:client_secret)
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Basic ")) {
            String decoded = new String(Base64.getDecoder().decode(authHeader.substring(6)));
            return decoded.split(":")[0]; // phần trước dấu :
        }

        return null;
    }

    private String extractUserId() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof User user) {
            return user.getId().toString();
        }
        return null;
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip != null && !ip.isBlank()) {
            return ip.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}