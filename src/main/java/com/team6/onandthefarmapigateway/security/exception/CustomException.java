package com.team6.onandthefarmapigateway.security.exception;

import lombok.Getter;

@Getter
public class CustomException extends RuntimeException {

    private final String message;
    private final int status;

    public CustomException(int status, String message) {
        this.status = status;
        this.message = message;
    }
}
