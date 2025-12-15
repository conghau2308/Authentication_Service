package com.Authentication.AuthService.services.auth;

import com.Authentication.AuthService.dto.EnrollResponseDto;
import com.Authentication.AuthService.dto.EnrollRequestWiFaKeyDto;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Service
@Slf4j
public class FaceAuthService {

    private final WebClient webClient;
    private final ObjectMapper objectMapper;

    @Value("${face.auth.timeout:30}")
    private int timeoutSeconds;

    public FaceAuthService(WebClient.Builder webClientBuilder,
            @Value("${face.auth.python.url}") String pythonApiUrl,
            ObjectMapper objectMapper) {
        this.webClient = webClientBuilder.baseUrl(pythonApiUrl).build();
        this.objectMapper = objectMapper;
    }

    /**
     * Custom exception để truyền thông tin lỗi chi tiết
     */
    public static class PythonApiException extends RuntimeException {
        private final String errorCode;
        private final int statusCode;

        public PythonApiException(String message, String errorCode, int statusCode) {
            super(message);
            this.errorCode = errorCode;
            this.statusCode = statusCode;
        }

        public String getErrorCode() {
            return errorCode;
        }

        public int getStatusCode() {
            return statusCode;
        }
    }

    /**
     * Parse error response từ Python API
     */
    private PythonApiException parsePythonError(String errorBody, int statusCode) {
        try {
            JsonNode jsonNode = objectMapper.readTree(errorBody);
            String detail = jsonNode.has("detail") ? jsonNode.get("detail").asText() : errorBody;
            String errorCode = jsonNode.has("error_code") ? jsonNode.get("error_code").asText() : "PYTHON_API_ERROR";

            log.debug("Parsed error - detail: {}, errorCode: {}", detail, errorCode);
            return new PythonApiException(detail, errorCode, statusCode);

        } catch (Exception e) {
            log.warn("Không thể parse error JSON, sử dụng raw error body");
            return new PythonApiException(errorBody, "PYTHON_API_ERROR", statusCode);
        }
    }

    /**
     * Enroll user với xử lý lỗi chi tiết
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
                            clientResponse -> clientResponse.bodyToMono(String.class)
                                    .flatMap(errorBody -> {
                                        int statusCode = clientResponse.statusCode().value();
                                        log.error("❌ Python API enroll thất bại - Status: {}, Body: {}",
                                                statusCode, errorBody);

                                        PythonApiException exception = parsePythonError(errorBody, statusCode);
                                        return Mono.error(exception);
                                    }))
                    .bodyToMono(EnrollResponseDto.class)
                    .timeout(Duration.ofSeconds(timeoutSeconds))
                    .doOnSuccess(resp -> {
                        if (resp != null) {
                            log.info("✅ Python API enroll thành công cho user: {}", username);
                        }
                    })
                    .block();

            return response;

        } catch (PythonApiException e) {
            // Ném lại exception với thông tin chi tiết để controller xử lý
            log.error("❌ Python API error: {} (code: {})", e.getMessage(), e.getErrorCode());
            throw e;

        } catch (WebClientResponseException e) {
            log.error("❌ WebClient error - Status: {}, Body: {}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            throw new PythonApiException(
                    "Lỗi kết nối đến Python API",
                    "CONNECTION_ERROR",
                    e.getStatusCode().value());

        } catch (Exception e) {
            log.error("❌ Lỗi không xác định: {}", e.getMessage());
            throw new PythonApiException(
                    "Lỗi hệ thống: " + e.getMessage(),
                    "SYSTEM_ERROR",
                    500);
        }
    }

    /**
     * Verify user với xử lý lỗi chi tiết
     */
    public boolean verifyUser(String username, String imageBase64,
            String helperData, String keyHash) {
        log.info("🔍 Đang gọi Python API verify cho user: {}", username);

        try {
            // Create verify request DTO
            var verifyRequest = new VerifyRequestWiFaKeyDto(imageBase64, helperData, keyHash);

            VerifyResponseDto response = webClient.post()
                    .uri("/verify/{username}", username)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(verifyRequest)
                    .retrieve()
                    .onStatus(
                            status -> status.is4xxClientError() || status.is5xxServerError(),
                            clientResponse -> clientResponse.bodyToMono(String.class)
                                    .flatMap(errorBody -> {
                                        int statusCode = clientResponse.statusCode().value();
                                        log.error("❌ Python API verify thất bại - Status: {}, Body: {}",
                                                statusCode, errorBody);

                                        PythonApiException exception = parsePythonError(errorBody, statusCode);
                                        return Mono.error(exception);
                                    }))
                    .bodyToMono(VerifyResponseDto.class)
                    .timeout(Duration.ofSeconds(timeoutSeconds))
                    .doOnSuccess(resp -> {
                        if (resp != null) {
                            log.info("✅ Python API verify response - success: {}", resp.isSuccess());
                        }
                    })
                    .block();

            return response != null && response.isSuccess();

        } catch (PythonApiException e) {
            log.error("❌ Python API verify error: {} (code: {})", e.getMessage(), e.getErrorCode());
            throw e;

        } catch (Exception e) {
            log.error("❌ Lỗi verify không xác định: {}", e.getMessage());
            throw new PythonApiException(
                    "Lỗi hệ thống khi verify: " + e.getMessage(),
                    "SYSTEM_ERROR",
                    500);
        }
    }
}

// DTO classes
class VerifyRequestWiFaKeyDto {
    private String image_b64;
    private String helper_data_b64;
    private String key_hash_b64;

    public VerifyRequestWiFaKeyDto(String image_b64, String helper_data_b64, String key_hash_b64) {
        this.image_b64 = image_b64;
        this.helper_data_b64 = helper_data_b64;
        this.key_hash_b64 = key_hash_b64;
    }

    // Getters
    public String getImage_b64() {
        return image_b64;
    }

    public String getHelper_data_b64() {
        return helper_data_b64;
    }

    public String getKey_hash_b64() {
        return key_hash_b64;
    }
}

class VerifyResponseDto {
    private boolean success;

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }
}