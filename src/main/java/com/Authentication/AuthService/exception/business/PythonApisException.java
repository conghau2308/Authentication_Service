package com.Authentication.AuthService.exception.business;

import org.springframework.http.HttpStatus;

import lombok.Getter;

@Getter
public class PythonApisException extends RuntimeException {
    private final String errorCode;
    private final HttpStatus status;

    public PythonApisException(String errorCode, String message, HttpStatus status) {
        super(message);
        this.errorCode = errorCode;
        this.status = status;
    }
}
