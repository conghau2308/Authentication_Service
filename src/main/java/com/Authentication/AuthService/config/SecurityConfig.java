package com.Authentication.AuthService.config;

import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
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

import jakarta.servlet.DispatcherType;
import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                CorsConfiguration configuration = new CorsConfiguration();
                configuration.setAllowedOrigins(List.of("http://localhost:3000", "http://localhost:3001",
                                "https://auth-developer-portal.vercel.app", "http://localhost:8080"));
                configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                configuration.setAllowedHeaders(Arrays.asList(
                                "Authorization", "Content-Type", "Accept", "X-Requested-With",
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

                                                // Public endpoints
                                                .requestMatchers("/.well-known/**").permitAll()
                                                .requestMatchers("/auth/**").permitAll()
                                                .requestMatchers("/oauth2/**").permitAll()
                                                .requestMatchers("/face-login").permitAll()
                                                .requestMatchers("/portal/login", "/portal/register").permitAll()
                                                .requestMatchers("/portal/demo-login").permitAll()
                                                .requestMatchers("/demo/**").permitAll()
                                                .requestMatchers("/error").permitAll()
                                                .requestMatchers(
                                                                "/swagger-ui/**",
                                                                "/v3/api-docs/**",
                                                                "/swagger-ui.html")
                                                .permitAll()

                                                // Static
                                                .requestMatchers("/css/**", "/js/**", "/images/**", "/favicon.ico")
                                                .permitAll()

                                                // Protected
                                                .requestMatchers("/portal/api/v1/enroll/**").authenticated()

                                                .anyRequest().authenticated())

                                // 🔥 Stateless vì dùng JWT
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                                // 🔥 Custom JWT filter của bạn
                               

                                .cors(Customizer.withDefaults())
                                .csrf(AbstractHttpConfigurer::disable);

                return http.build();
        }
}