package com.Authentication.AuthService.services.auth;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import com.Authentication.AuthService.dto.EnrollRequestWiFaKeyDto;
import com.Authentication.AuthService.dto.EnrollResponseDto;
import com.Authentication.AuthService.dto.VerifyRequestDto;
import com.Authentication.AuthService.dto.VerifyResponseDto;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Service
@Slf4j
public class FaceAuthService {
    private final WebClient webClient;

    @Value("${wifakey.service.timeout:60}")
    private long timeoutSeconds;

    public FaceAuthService(WebClient webClient) {
        this.webClient = webClient;
    }

    /***
     * Đăng ký khuôn mặt người dùng-Gọi Python API
     */

    public EnrollResponseDto enrollUser(String username, String imageBase64) {
        log.info("🔵 Đang gọi Python API enroll cho user: {}", username);

        EnrollRequestWiFaKeyDto enrollRequestWiFaKeyDto = new EnrollRequestWiFaKeyDto(imageBase64);

        try {
            EnrollResponseDto response = webClient.post()
                    .uri("/enroll/{username}", username)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(enrollRequestWiFaKeyDto)
                    .retrieve()
                    .onStatus(
                            status -> status.is4xxClientError() || status.is5xxServerError(),
                            clientResponse -> {
                                log.error("❌ Python API enroll thất bại - Status: {}", clientResponse.statusCode());
                                return clientResponse.bodyToMono(String.class)
                                        .flatMap(errorBody -> {
                                            log.error("❌ Error body: {}", errorBody);
                                            return Mono.error(new RuntimeException("Python API error: " + errorBody));
                                        });
                            })
                    .bodyToMono(EnrollResponseDto.class)
                    .timeout(Duration.ofSeconds(timeoutSeconds))
                    .block();

            if (response != null) {
                log.info("✅ Python API enroll thành công cho user: {}", username);
                log.debug("Helper data length: {}, Key hash length: {}",
                        response.getHelper_data_b64() != null ? response.getHelper_data_b64().length() : 0,
                        response.getKey_hash_b64() != null ? response.getKey_hash_b64().length() : 0);
            }

            return response;

        } catch (WebClientResponseException e) {
            log.error("❌ Python API enroll error - Status: {}, Body: {}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            return null;

        } catch (Exception e) {
            log.error("❌ Lỗi kết nối Python API enroll: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Xác thực khuôn mặt người dùng - Gọi Python API
     */
    public boolean verifyUser(String username, String imageBase64, String helperDataB64, String keyHashB64) {
        log.info("🟢 Đang gọi Python API verify cho user: {}", username);

        try {
            VerifyRequestDto verifyRequest = new VerifyRequestDto(helperDataB64, keyHashB64, imageBase64);

            VerifyResponseDto response = webClient.post()
                    .uri("/verify/{username}", username)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(verifyRequest)
                    .retrieve()
                    .onStatus(
                            status -> status.is4xxClientError() || status.is5xxServerError(),
                            clientResponse -> {
                                log.error("❌ Python API verify thất bại - Status: {}", clientResponse.statusCode());
                                return clientResponse.bodyToMono(String.class)
                                        .flatMap(errorBody -> {
                                            log.error("❌ Error body: {}", errorBody);
                                            return Mono.error(new RuntimeException("Python API error: " + errorBody));
                                        });
                            })
                    .bodyToMono(VerifyResponseDto.class)
                    .timeout(Duration.ofSeconds(timeoutSeconds))
                    .block();

            boolean success = response != null && response.isSuccess();
            log.info("✅ Python API verify kết quả: {}", success ? "THÀNH CÔNG" : "THẤT BẠI");

            return success;

        } catch (WebClientResponseException e) {
            log.error("❌ Python API verify error - Status: {}, Body: {}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            return false;

        } catch (Exception e) {
            log.error("❌ Lỗi kết nối Python API verify: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Đăng ký bất đồng bộ (Non-blocking)
     */
    public Mono<EnrollResponseDto> enrollUserAsync(String username) {
        log.info("🔵 [ASYNC] Đang gọi Python API enroll cho user: {}", username);

        return webClient.post()
                .uri("/enroll/{username}", username)
                .contentType(MediaType.APPLICATION_JSON)
                .retrieve()
                .onStatus(
                        status -> status.is4xxClientError() || status.is5xxServerError(),
                        clientResponse -> {
                            log.error("❌ [ASYNC] Python API enroll thất bại - Status: {}", clientResponse.statusCode());
                            return clientResponse.bodyToMono(String.class)
                                    .flatMap(errorBody -> Mono
                                            .error(new RuntimeException("Python API error: " + errorBody)));
                        })
                .bodyToMono(EnrollResponseDto.class)
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .doOnSuccess(response -> log.info("✅ [ASYNC] Python API enroll thành công cho user: {}", username))
                .doOnError(error -> log.error("❌ [ASYNC] Lỗi kết nối Python API enroll: {}", error.getMessage()));
    }

    /**
     * Xác thực bất đồng bộ (Non-blocking)
     */
    public Mono<Boolean> verifyUserAsync(String username, String imageBase64, String helperDataB64, String keyHashB64) {
        log.info("🟢 [ASYNC] Đang gọi Python API verify cho user: {}", username);

        VerifyRequestDto verifyRequest = new VerifyRequestDto(imageBase64, helperDataB64, keyHashB64);

        return webClient.post()
                .uri("/verify/{username}", username)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(verifyRequest)
                .retrieve()
                .onStatus(
                        status -> status.is4xxClientError() || status.is5xxServerError(),
                        clientResponse -> {
                            log.error("❌ [ASYNC] Python API verify thất bại - Status: {}", clientResponse.statusCode());
                            return clientResponse.bodyToMono(String.class)
                                    .flatMap(errorBody -> Mono
                                            .error(new RuntimeException("Python API error: " + errorBody)));
                        })
                .bodyToMono(VerifyResponseDto.class)
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .map(VerifyResponseDto::isSuccess)
                .doOnSuccess(success -> log.info("✅ [ASYNC] Python API verify kết quả: {}",
                        success ? "THÀNH CÔNG" : "THẤT BẠI"))
                .doOnError(error -> log.error("❌ [ASYNC] Lỗi kết nối Python API verify: {}", error.getMessage()))
                .onErrorReturn(false);
    }

    public boolean verifyUser(String username) {
        log.warn("Bỏ qua xác thực khuôn mặt");
        return true;
    }
}
