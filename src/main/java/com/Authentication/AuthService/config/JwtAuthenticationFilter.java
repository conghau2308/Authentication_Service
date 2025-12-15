package com.Authentication.AuthService.config;

import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.services.auth.AuthJwtService;
import com.Authentication.AuthService.services.auth.CustomUserDetailsService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final AuthJwtService jwtService;
    private final CustomUserDetailsService userDetailsService;

    private static final String ACCESS_TOKEN_COOKIE = "access_token";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        try {
            // 1. Get token from Cookie first
            String jwt = getTokenFromCookie(request);

            // 2. Fallback to Authorization header
            if (jwt == null) {
                final String authHeader = request.getHeader("Authorization");
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    jwt = authHeader.substring(7);
                }
            }

            if (jwt != null) {
                final String username = jwtService.extractUsername(jwt);

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    if (jwtService.validateToken(jwt, username)) {

                        // ✅ Load User entity thay vì chỉ username
                        User user = userDetailsService.loadUserEntityByUsername(username);

                        // ✅ Set User entity làm principal
                        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                                user, // ✅ User entity, không phải String username
                                null,
                                List.of(new SimpleGrantedAuthority("ROLE_USER")));

                        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authToken);

                        log.debug("✅ Authenticated user: {} (ID: {})", username, user.getId());
                    }
                }
            }
        } catch (Exception e) {
            log.error("❌ Cannot set authentication: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Get JWT token from HTTP-Only cookie
     */
    private String getTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() != null) {
            return Arrays.stream(request.getCookies())
                    .filter(cookie -> ACCESS_TOKEN_COOKIE.equals(cookie.getName()))
                    .map(Cookie::getValue)
                    .findFirst()
                    .orElse(null);
        }
        return null;
    }
}