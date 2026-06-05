package com.Authentication.AuthService.exception.business;

import lombok.Getter;

@Getter
public class RateLimitExceededException extends RuntimeException {

    private final long retryAfterSeconds;

    public RateLimitExceededException(long retryAfterSeconds) {
        super("Quá nhiều request. Vui lòng thử lại sau.");
        this.retryAfterSeconds = retryAfterSeconds;
    }
}
