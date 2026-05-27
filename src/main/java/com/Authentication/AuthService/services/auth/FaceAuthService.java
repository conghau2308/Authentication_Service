package com.Authentication.AuthService.services.auth;

import com.Authentication.AuthService.dto.UserEnrollResponseDto;
import com.Authentication.AuthService.dto.EnrollRequestWiFaKeyDto;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import com.Authentication.AuthService.exception.business.PythonApisException;
import org.springframework.http.HttpStatus;
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
     * Parse error response từ Python API
     */
    private PythonApisException parsePythonError(String errorBody, int statusCode) {
        try {
            JsonNode jsonNode = objectMapper.readTree(errorBody);
            String detail = jsonNode.has("detail") ? jsonNode.get("detail").asText() : errorBody;
            String errorCode = jsonNode.has("error_code") ? jsonNode.get("error_code").asText() : "PYTHON_API_ERROR";

            log.debug("Parsed error - detail: {}, errorCode: {}", detail, errorCode);
            return new PythonApisException(errorCode, detail, HttpStatus.valueOf(statusCode));

        } catch (Exception e) {
            log.warn("Không thể parse error JSON, sử dụng raw error body");
            return new PythonApisException("PYTHON_API_ERROR", errorBody, HttpStatus.valueOf(statusCode));
        }
    }

    /**
     * Enroll user với xử lý lỗi chi tiết
     */
    public UserEnrollResponseDto enrollUser(String username, String imageBase64) {
        log.info("🔵 Đang gọi Python API enroll cho user: {}", username);

        EnrollRequestWiFaKeyDto enrollRequestWiFaKeyDto = new EnrollRequestWiFaKeyDto(imageBase64);

        try {
            UserEnrollResponseDto response = webClient.post()
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

                                        PythonApisException exception = parsePythonError(errorBody, statusCode);
                                        return Mono.error(exception);
                                    }))
                    .bodyToMono(UserEnrollResponseDto.class)
                    .timeout(Duration.ofSeconds(timeoutSeconds))
                    .doOnSuccess(resp -> {
                        if (resp != null) {
                            log.info("✅ Python API enroll thành công cho user: {}", username);
                        }
                    })
                    .block();

            return response;

        } catch (PythonApisException e) {
            // Ném lại exception với thông tin chi tiết để controller xử lý
            log.error("❌ Python API error: {} (code: {})", e.getMessage(), e.getErrorCode());
            throw e;

        } catch (WebClientResponseException e) {
            log.error("❌ WebClient error - Status: {}, Body: {}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            throw new PythonApisException(
                    "CONNECTION_ERROR",
                    "Lỗi kết nối đến Python API",
                    (HttpStatus) e.getStatusCode());

        } catch (Exception e) {
            log.error("❌ Lỗi không xác định: {}", e.getMessage());
            throw new PythonApisException(
                    "SYSTEM_ERROR",
                    "Lỗi hệ thống: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Verify user với xử lý lỗi chi tiết
     */
    public boolean verifyUser(String username, String imageBase64,
            String helperData, String mask, String keyHash) {
        log.info("🔍 Đang gọi Python API verify cho user: {}", username);

        try {
            // Create verify request DTO
            var verifyRequest = new VerifyRequestWiFaKeyDto(imageBase64, helperData, mask, keyHash);

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

                                        PythonApisException exception = parsePythonError(errorBody, statusCode);
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

        } catch (PythonApisException e) {
            log.error("❌ Python API verify error: {} (code: {})", e.getMessage(), e.getErrorCode());
            throw e;

        } catch (Exception e) {
            log.error("❌ Lỗi verify không xác định: {}", e.getMessage());
            throw new PythonApisException(
                    "SYSTEM_ERROR",
                    "Lỗi hệ thống khi verify: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}

// DTO classes
class VerifyRequestWiFaKeyDto {
    @com.fasterxml.jackson.annotation.JsonProperty("image")
    private String image_b64;
    private String helper_data_b64;
    private String mask_b64;
    private String key_hash_b64;

    public VerifyRequestWiFaKeyDto(String image_b64, String helper_data_b64, String mask_b64, String key_hash_b64) {
        this.image_b64 = image_b64;
        this.helper_data_b64 = helper_data_b64;
        this.mask_b64 = mask_b64;
        this.key_hash_b64 = key_hash_b64;
    }

    // Getters
    public String getImage_b64() {
        return image_b64;
    }

    public String getHelper_data_b64() {
        return helper_data_b64;
    }

    public String getMask_b64() {
        return mask_b64;
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