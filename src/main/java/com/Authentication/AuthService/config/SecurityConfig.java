package com.Authentication.AuthService.config;

import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jakarta.servlet.DispatcherType;

@Configuration
public class SecurityConfig {

        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                CorsConfiguration configuration = new CorsConfiguration();
                configuration.setAllowedOrigins(List.of("http://localhost:3001", "http://localhost:3000"));
                configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                configuration.setAllowedHeaders(Arrays.asList(
                                "Authorization", "Content-Type", "Accept", "X-Requested-With"));
                configuration.setAllowCredentials(true);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);
                return source;
        }

        @Bean
        @Order(1)
        public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
                OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

                RequestMatcher authorizationServerMatcher = new OrRequestMatcher(
                                new AntPathRequestMatcher("/.well-known/oauth-authorization-server"),
                                new AntPathRequestMatcher("/.well-known/openid-configuration"),
                                new AntPathRequestMatcher("/oauth2/introspect"),
                                new AntPathRequestMatcher("/oauth2/revoke"),
                                new AntPathRequestMatcher("/.well-known/jwks.json"),
                                new AntPathRequestMatcher("/userinfo"));

                http
                                .securityMatcher(authorizationServerMatcher)
                                .with(authorizationServerConfigurer, configurer -> {
                                        configurer.oidc(Customizer.withDefaults());
                                })
                                // ✅ FIX: Cho phép public access đến JWKS endpoints
                                .authorizeHttpRequests(authorize -> authorize
                                                .requestMatchers("/.well-known/jwks.json").permitAll()
                                                .requestMatchers("/.well-known/openid-configuration").permitAll()
                                                .anyRequest().authenticated())
                                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                                .cors(Customizer.withDefaults())
                                .csrf(AbstractHttpConfigurer::disable);

                return http.build();
        }

        @Bean
        @Order(2)
        public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
                http
                                .authorizeHttpRequests(authorize -> authorize
                                                .dispatcherTypeMatchers(DispatcherType.FORWARD, DispatcherType.INCLUDE)
                                                .permitAll()

                                                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                                                // ✅ JWKS endpoints - public access
                                                .requestMatchers("/.well-known/**").permitAll()

                                                .requestMatchers("/face-auth/**").permitAll()

                                                // ✅ OAuth2 custom endpoints
                                                .requestMatchers("/oauth2/authorize/validate").permitAll()
                                                .requestMatchers("oauth2/authenticate").permitAll()
                                                .requestMatchers("/oauth2/token").permitAll()
                                                .requestMatchers("/oauth2/face-auth/login").permitAll()
                                                .requestMatchers("/oauth2/revoke").permitAll()
                                                .requestMatchers("/oauth2/userinfo").permitAll()

                                                // ✅ Face login page
                                                .requestMatchers("/face-login").permitAll()

                                                // ✅ Portal endpoints
                                                .requestMatchers("/portal/demo-login").permitAll()
                                                .requestMatchers("/portal/login", "/portal/register").permitAll()
                                                .requestMatchers("/portal/api/**").permitAll()

                                                // ✅ Demo endpoints
                                                .requestMatchers("/demo/**").permitAll()

                                                // ✅ Error page
                                                .requestMatchers("/error").permitAll()

                                                // Static resources
                                                .requestMatchers("/css/**", "/js/**", "/images/**", "/favicon.ico")
                                                .permitAll()

                                                .anyRequest().authenticated())
                                // ✅ QUAN TRỌNG NHẤT
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))

                                // ✅ QUAN TRỌNG NHẤT
                                .securityContext(securityContext -> securityContext.requireExplicitSave(false))

                                .logout(logout -> logout
                                                .logoutUrl("/logout")
                                                .logoutSuccessUrl("/portal/login?logout")
                                                .invalidateHttpSession(true)
                                                .deleteCookies("JSESSIONID"))
                                .cors(Customizer.withDefaults())
                                .csrf(AbstractHttpConfigurer::disable);

                return http.build();
        }
}