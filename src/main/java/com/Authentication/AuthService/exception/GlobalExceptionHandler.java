package com.Authentication.AuthService.exception;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.server.ResponseStatusException;

import com.Authentication.AuthService.dto.response.ApiResponse;
import com.Authentication.AuthService.exception.business.BusinessException;
import com.Authentication.AuthService.exception.business.PythonApisException;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {
        @ExceptionHandler(MethodArgumentNotValidException.class)
        public ResponseEntity<ApiResponse<Object>> handleValidExceptions(MethodArgumentNotValidException exception) {
                Map<String, String> errors = new HashMap<>();
                exception.getBindingResult().getFieldErrors()
                                .forEach(error -> errors.put(error.getField(), error.getDefaultMessage()));

                return ResponseEntity.badRequest().body(
                                ApiResponse.error("Dữ liệu không hợp lệ", errors));
        }

        @ExceptionHandler(MethodArgumentTypeMismatchException.class)
        public ResponseEntity<ApiResponse<Object>> handleTypeMismatch(MethodArgumentTypeMismatchException ex) {
                String field = ex.getName();
                String value = ex.getValue() != null ? ex.getValue().toString() : "null";
                String expectedType = ex.getRequiredType() != null ? ex.getRequiredType().getSimpleName() : "unknown";

                Map<String, String> errors = new HashMap<>();
                errors.put(field, String.format("Giá trị '%s' không hợp lệ, yêu cầu kiểu %s", value, expectedType));

                return ResponseEntity.badRequest()
                                .body(ApiResponse.error("Tham số không hợp lệ", errors));
        }

        @ExceptionHandler(BusinessException.class)
        public ResponseEntity<ApiResponse<Object>> handleBusinessException(BusinessException exception) {
                return ResponseEntity.status(exception.getStatus()).body(
                                ApiResponse.error(exception.getMessage(), exception.getCode()));
        }

        @ExceptionHandler(PythonApisException.class)
        public ResponseEntity<ApiResponse<Object>> handlePythonException(PythonApisException exception) {
                return ResponseEntity.status(exception.getStatus()).body(
                                ApiResponse.error(exception.getMessage(), exception.getErrorCode()));
        }

        @ExceptionHandler(ResponseStatusException.class)
        public ResponseEntity<ApiResponse<Object>> handleResponseStatusException(
                        ResponseStatusException ex) {

                // Phân biệt rate limit với các ResponseStatusException khác
                boolean isRateLimit = ex.getStatusCode() == HttpStatus.TOO_MANY_REQUESTS;
                String code = isRateLimit ? "RATE_LIMIT_EXCEEDED" : ex.getStatusCode().toString();
                String message = ex.getReason() != null ? ex.getReason() : ex.getMessage();

                return ResponseEntity.status(ex.getStatusCode()).body(
                                ApiResponse.error(message, code));
        }

        // Xử lý lỗi chung chung
        @ExceptionHandler(Exception.class)
        public ResponseEntity<ApiResponse<Object>> handleSystemExceptions(Exception exception) {
                log.error("System exception caught", exception);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                                ApiResponse.<Object>builder()
                                                .success(false)
                                                .message("Đã xảy ra lỗi hệ thống. Vui lòng thử lại sau.")
                                                .build());
        }
}
