package com.Authentication.AuthService.aspect;

import java.lang.reflect.Method;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.Authentication.AuthService.annotation.RateLimit;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.enums.LimitStrategy;
import com.Authentication.AuthService.exception.business.RateLimitExceededException;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.distributed.BucketProxy;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Aspect
@Component
@Slf4j
@RequiredArgsConstructor
public class RateLimitAspect {

    private final LettuceBasedProxyManager<String> rateLimitProxyManager;

    @Around("execution(* com.Authentication.AuthService.controller..*.*(..))")
    public Object around(ProceedingJoinPoint joinPoint) throws Throwable {

        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        RateLimit rateLimit = method.getAnnotation(RateLimit.class);
        if (rateLimit == null) {
            rateLimit = joinPoint.getTarget().getClass().getAnnotation(RateLimit.class);
        }

        int limit    = (rateLimit != null) ? rateLimit.limit()           : 50;
        int duration = (rateLimit != null) ? rateLimit.durationSeconds() : 60;
        LimitStrategy strategy = (rateLimit != null) ? rateLimit.strategy() : LimitStrategy.BY_IP;

        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder
                .currentRequestAttributes()).getRequest();

        String bucketKey = resolveBucketKey(request, strategy,
                joinPoint.getSignature().toShortString());

        BucketConfiguration config = BucketConfiguration.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(limit)
                        .refillGreedy(limit, Duration.ofSeconds(duration))
                        .build())
                .build();

        BucketProxy bucket = rateLimitProxyManager.builder()
                .build(bucketKey, () -> config);

        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);

        if (probe.isConsumed()) {
            return joinPoint.proceed();
        }

        long retryAfterSeconds = TimeUnit.NANOSECONDS.toSeconds(
                probe.getNanosToWaitForRefill()) + 1;

        log.warn("Rate limit exceeded - strategy: {}, key: {}, retry-after: {}s",
                strategy, bucketKey, retryAfterSeconds);

        throw new RateLimitExceededException(retryAfterSeconds);
    }

    private String resolveBucketKey(HttpServletRequest request,
            LimitStrategy strategy, String methodKey) {
        String ip = getClientIp(request);

        return switch (strategy) {
            case BY_IP -> "ip:" + ip + ":" + methodKey;

            case BY_CLIENT_ID -> {
                String clientId = extractClientId(request);
                // Fallback to IP — không bao giờ skip rate limiting
                yield clientId != null
                        ? "client:" + clientId + ":" + methodKey
                        : "ip:" + ip + ":" + methodKey;
            }

            case BY_USER -> {
                String userId = extractUserId();
                // Fallback to IP khi chưa authed
                yield userId != null
                        ? "user:" + userId + ":" + methodKey
                        : "ip:" + ip + ":" + methodKey;
            }

            case BY_IP_AND_CLIENT_ID -> {
                String clientId = extractClientId(request);
                yield clientId != null
                        ? "ipclient:" + ip + ":" + clientId + ":" + methodKey
                        : "ip:" + ip + ":" + methodKey;
            }
        };
    }

    private String extractClientId(HttpServletRequest request) {
        String clientId = request.getParameter("client_id");
        if (clientId != null) return clientId;

        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Basic ")) {
            try {
                String decoded = new String(Base64.getDecoder()
                        .decode(authHeader.substring(6)));
                return decoded.split(":", 2)[0];
            } catch (IllegalArgumentException e) {
                return null;
            }
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
        // server.forward-headers-strategy=framework đã set → ForwardedHeaderFilter
        // đã rewrite getRemoteAddr() về đúng client IP trước khi AOP aspect chạy.
        return request.getRemoteAddr();
    }
}
