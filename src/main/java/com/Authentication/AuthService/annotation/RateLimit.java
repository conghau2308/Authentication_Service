package com.Authentication.AuthService.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.Authentication.AuthService.enums.LimitStrategy;

@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface RateLimit {
    int limit() default 50;

    int durationSeconds() default 60;

    LimitStrategy strategy() default LimitStrategy.BY_IP;
}
