package com.Authentication.AuthService.exception;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

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
