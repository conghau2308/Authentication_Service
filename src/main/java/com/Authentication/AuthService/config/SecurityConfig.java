package com.Authentication.AuthService.config;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.Authentication.AuthService.filter.JwtAuthFilter;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
        private final JwtAuthFilter jwtAuthFilter; // ✅ Inject filter vào

        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                CorsConfiguration configuration = new CorsConfiguration();
                configuration.setAllowedOrigins(List.of("http://localhost:3000", "http://localhost:3001",
                                "https://auth-developer-portal.vercel.app", "http://localhost:8080"));
                configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
                configuration.setAllowedHeaders(List.of(
                                "Authorization",
                                "Content-Type",
                                "Accept",
                                "X-Requested-With",
                                "ngrok-skip-browser-warning"));
                configuration.setAllowCredentials(true);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);
                return source;
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http
                                .authorizeHttpRequests(authorize -> authorize
                                                .dispatcherTypeMatchers(DispatcherType.FORWARD, DispatcherType.INCLUDE)
                                                .permitAll()
                                                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                                                .requestMatchers(
                                                                "/swagger-ui/**",
                                                                "/v3/api-docs/**",
                                                                "/swagger-ui.html")
                                                .permitAll()
                                                .requestMatchers("/css/**", "/js/**", "/images/**", "/favicon.ico")
                                                .permitAll()
                                                .requestMatchers("/.well-known/**", "/error").permitAll()
                                                .requestMatchers(HttpMethod.POST, "/auth/enroll").permitAll()
                                                .requestMatchers(HttpMethod.POST, "/auth/verify").permitAll()
                                                .requestMatchers(HttpMethod.GET, "/invitations/preview").permitAll()
                                                .requestMatchers(HttpMethod.POST, "/auth/check-username").permitAll()
                                                .requestMatchers(HttpMethod.POST, "/auth/check-email").permitAll()
                                                .requestMatchers(HttpMethod.GET, "/oauth2/validate").permitAll()
                                                .requestMatchers(HttpMethod.GET, "/oauth2/userinfo").permitAll()
                                                .requestMatchers(HttpMethod.GET, "/auth/delta").permitAll()
                                                .requestMatchers(HttpMethod.POST, "/auth/refresh").permitAll() // ← thêm
                                                                                                               // dòng
                                                                                                               // này
                                                .requestMatchers(HttpMethod.POST, "/auth/logout").permitAll() // ←
                                                                                                              // logout
                                                                                                              // cũng
                                                                                                              // vậy
                                                .anyRequest().authenticated())

                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                                // ── Thêm đoạn này ──────────────────────────────────────
                                .exceptionHandling(ex -> ex
                                                .authenticationEntryPoint((request, response, authException) -> {
                                                        // Không có token → 401, không phải 403
                                                        writeErrorResponse(response, "MISSING_TOKEN",
                                                                        "Vui lòng đăng nhập để tiếp tục.",
                                                                        HttpStatus.UNAUTHORIZED);
                                                })
                                                .accessDeniedHandler((request, response, accessDeniedException) -> {
                                                        // Đã auth nhưng không đủ quyền → 403 thực sự
                                                        writeErrorResponse(response, "ACCESS_DENIED",
                                                                        "Bạn không có quyền truy cập tài nguyên này.",
                                                                        HttpStatus.FORBIDDEN);
                                                }))
                                // ────────────────────────────────────────────────────────

                                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                                .cors(Customizer.withDefaults())
                                .csrf(AbstractHttpConfigurer::disable);

                return http.build();
        }

        // Helper dùng chung với JwtAuthFilter — nên extract ra 1 utility class
        private void writeErrorResponse(HttpServletResponse response,
                        String code, String message, HttpStatus status) throws IOException {
                response.setStatus(status.value());
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");

                Map<String, Object> body = new LinkedHashMap<>();
                body.put("code", code);
                body.put("message", message);
                body.put("timestamp", LocalDateTime.now().toString());

                new ObjectMapper().writeValueAsString(body);
                response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        }
}