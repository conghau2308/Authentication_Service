package com.Authentication.AuthService.config;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.netty.http.client.HttpClient;

@Configuration
public class WebClientConfig {
    @Value("${wifakey.service.url:http://localhost:8000}")
    private String wifakeyServiceUrl;

    @Bean
    public WebClient webClient() {
        HttpClient httpClient = HttpClient.create()
                .responseTimeout(Duration.ofSeconds(60)) // Timeout cho response
                .option(io.netty.channel.ChannelOption.CONNECT_TIMEOUT_MILLIS, 30000); // Timeout kết nối

        return WebClient.builder()
                .baseUrl(wifakeyServiceUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
    }
}
