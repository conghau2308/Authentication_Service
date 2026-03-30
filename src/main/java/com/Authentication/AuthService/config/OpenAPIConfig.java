package com.Authentication.AuthService.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenAPIConfig {

        @Bean
        public OpenAPI myOpenAPI() {
                Server devServer = new Server();
                devServer.setUrl("http://localhost:8080");
                devServer.setDescription("Server URL in Development environment");

                Server prodServer = new Server();
                prodServer.setUrl("https://api.production.com");
                prodServer.setDescription("Server URL in Production environment");

                Contact contact = new Contact();
                contact.setEmail("contact@example.com");
                contact.setName("Your Name");
                contact.setUrl("https://www.example.com");

                License mitLicense = new License()
                                .name("MIT License")
                                .url("https://choosealicense.com/licenses/mit/");

                Info info = new Info()
                                .title("API Documentation")
                                .version("1.0")
                                .contact(contact)
                                .description("API documentation for Spring Boot application")
                                .license(mitLicense);

                SecurityScheme bearerScheme = new SecurityScheme()
                                .name("bearerAuth")
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .in(SecurityScheme.In.HEADER)
                                .description("Paste token lấy từ response của /auth/verify");

                // ← khai báo trước khi dùng
                SecurityRequirement securityRequirement = new SecurityRequirement()
                                .addList("bearerAuth");

                return new OpenAPI()
                                .info(info)
                                .servers(List.of(devServer, prodServer))
                                .components(new Components()
                                                .addSecuritySchemes("bearerAuth", bearerScheme))
                                .addSecurityItem(securityRequirement);
        }
}
