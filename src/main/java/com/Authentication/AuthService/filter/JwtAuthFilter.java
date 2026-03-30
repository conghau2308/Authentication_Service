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
    private final ObjectMapper objectMapper; // inject để viết JSON response

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {
        log.debug("Auth header: {}", request.getHeader("Authorization"));

        String token = extractTokenFromHeader(request);
        log.debug("Extracted token: {}", token != null ? "present" : "null");
        if (token == null) {
            token = extractTokenFromCookie(request);
        }

        // Không có token → cho đi tiếp, Security sẽ chặn nếu endpoint cần auth
        if (token == null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            UUID id = UUID.fromString(authJwtService.extractUserId(token));

            if (id != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                User user = userRepository.findById(id)
                        .orElseThrow(() -> new BusinessException(
                                "USER_NOT_FOUND",
                                "Không tìm thấy user trên hệ thống.",
                                HttpStatus.UNAUTHORIZED));

                if (authJwtService.validateAccessToken(token, id.toString())) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            user, null, user.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                } else {
                    // Token không hợp lệ → trả lỗi luôn
                    writeErrorResponse(response, "INVALID_TOKEN", "Access token không hợp lệ.");
                    return;
                }
            }

        } catch (JwtException | IllegalArgumentException e) {
            // Token sai format/hết hạn → trả lỗi luôn
            writeErrorResponse(response, "INVALID_TOKEN", "Access token không hợp lệ.");
            return;

        } catch (BusinessException e) {
            // User không tồn tại
            writeErrorResponse(response, e.getCode(), e.getMessage());
            return;
        }

        filterChain.doFilter(request, response);
    }

    // Tách method viết JSON response lỗi
    private void writeErrorResponse(HttpServletResponse response,
            String code,
            String message) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
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