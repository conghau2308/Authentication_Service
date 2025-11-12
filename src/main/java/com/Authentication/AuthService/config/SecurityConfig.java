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
        configuration.setAllowedOrigins(List.of("http://localhost:3000"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList(
            "Authorization", "Content-Type", "Accept", "X-Requested-With"
        ));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = 
            new OAuth2AuthorizationServerConfigurer();

        RequestMatcher excludeAuthorizeMatcher = new OrRequestMatcher(
            new AntPathRequestMatcher("/oauth2/token"),
            new AntPathRequestMatcher("/oauth2/introspect"),
            new AntPathRequestMatcher("/oauth2/revoke"),
            new AntPathRequestMatcher("/oauth2/jwks"),
            new AntPathRequestMatcher("/.well-known/**"),
            new AntPathRequestMatcher("/userinfo")
        );

        http
            .securityMatcher(excludeAuthorizeMatcher)
            .with(authorizationServerConfigurer, configurer -> {
                configurer.oidc(Customizer.withDefaults());
            })
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            )
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
                // ✅ CHO PHÉP TẤT CẢ FORWARD VÀ INCLUDE REQUESTS
                .dispatcherTypeMatchers(DispatcherType.FORWARD, DispatcherType.INCLUDE)
                    .permitAll()
                
                // ✅ Cho phép OPTIONS requests
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                
                // ✅ OAuth2 custom endpoints
                .requestMatchers("/oauth2/authorize").permitAll()
                .requestMatchers("/oauth2/face-auth/login").permitAll()
                
                // ✅ Face login page - CHO PHÉP CẢ FORWARD
                .requestMatchers("/face-login").permitAll()
                
                // ✅ Portal endpoints
                .requestMatchers("/portal/demo-login").permitAll()
                .requestMatchers("/portal/login", "/portal/register").permitAll()
                .requestMatchers("/portal/api/**").hasRole("DEVELOPER")
                
                // ✅ Error page
                .requestMatchers("/error").permitAll()
                
                // Static resources
                .requestMatchers("/css/**", "/js/**", "/images/**", "/favicon.ico").permitAll()
                
                // All other requests require authentication
                .anyRequest().authenticated()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/portal/login?logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
            )
            .cors(Customizer.withDefaults())
            .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }
}