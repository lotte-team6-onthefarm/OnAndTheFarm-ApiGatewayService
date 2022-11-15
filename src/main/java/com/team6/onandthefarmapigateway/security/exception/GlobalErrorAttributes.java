package com.team6.onandthefarmapigateway.security.exception;

import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.reactive.error.DefaultErrorAttributes;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;

import java.util.Map;

@Component
public class GlobalErrorAttributes extends DefaultErrorAttributes {

    @Override
    public Map<String, Object> getErrorAttributes(ServerRequest request,
                                                  ErrorAttributeOptions options) {
        Map<String, Object> map = super.getErrorAttributes(request, options);

        Throwable throwable = getError(request);
        if (throwable instanceof CustomException) {
            CustomException customException = (CustomException) getError(request);
            map.put("exception", customException.getClass().getSimpleName());
            map.put("message", customException.getMessage());
            map.put("status", customException.getStatus());
        }
        return map;
    }
}
