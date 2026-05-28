package com.Authentication.AuthService.filter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.Authentication.AuthService.config.CookieConfig;
import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.exception.business.BusinessException;
import com.Authentication.AuthService.repository.UserRepository;
import com.Authentication.AuthService.services.auth.AuthJwtService;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

    private final CookieConfig cookieConfig;
    private final AuthJwtService authJwtService;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        return path.startsWith("/oauth2/userinfo")
                || path.startsWith("/oauth2/token")
                || path.startsWith("/oauth2/refresh")
                || path.startsWith("/oauth2/revoke")
                || path.startsWith("/oauth2/validate");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        String token = extractTokenFromHeader(request);
        log.debug("Auth header: {}", request.getHeader("Authorization"));
        log.debug("Extracted token from header: {}", token != null ? "present" : "null");

        if (token == null) {
            token = extractTokenFromCookie(request);
            log.debug("Extracted token from cookie: {}", token != null ? "present" : "null");
        }

        // Không có token → cho đi tiếp, Security config sẽ chặn nếu endpoint cần auth
        if (token == null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // Validate token trước — throw ngay nếu expired hoặc invalid
            Claims claims = authJwtService.validateAndExtractClaims(token);
            UUID id = UUID.fromString(claims.getSubject());

            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                // Query DB chỉ sau khi token đã được xác nhận hợp lệ
                User user = userRepository.findById(id)
                        .orElseThrow(() -> new BusinessException(
                                "USER_NOT_FOUND",
                                "Không tìm thấy user trên hệ thống.",
                                HttpStatus.UNAUTHORIZED));

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(user, null,
                        user.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);

                log.debug("Authenticated user: {}", id);
            }

        } catch (ExpiredJwtException e) {
            log.debug("Token expired: {}", e.getMessage());
            writeErrorResponse(response, "TOKEN_EXPIRED", "Access token đã hết hạn.", HttpStatus.UNAUTHORIZED);
            return;

        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Invalid token: {}", e.getMessage());
            writeErrorResponse(response, "INVALID_TOKEN", "Access token không hợp lệ.", HttpStatus.UNAUTHORIZED);
            return;

        } catch (BusinessException e) {
            log.debug("Business error in auth filter: {}", e.getMessage());
            writeErrorResponse(response, e.getCode(), e.getMessage(), HttpStatus.UNAUTHORIZED);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void writeErrorResponse(HttpServletResponse response,
            String code,
            String message,
            HttpStatus status) throws IOException {
        response.setStatus(status.value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", code);
        body.put("message", message);
        body.put("timestamp", LocalDateTime.now().toString());

        response.getWriter().write(objectMapper.writeValueAsString(body));
    }

    private String extractTokenFromHeader(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    private String extractTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null)
            return null;

        return Arrays.stream(request.getCookies())
                .filter(cookie -> cookieConfig.getAccessTokenName().equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }
}