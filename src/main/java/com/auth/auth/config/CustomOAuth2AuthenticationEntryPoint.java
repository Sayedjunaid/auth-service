package com.auth.auth.config;


import com.auth.auth.model.GenericResponse;
import com.nimbusds.jose.shaded.gson.Gson;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.StringJoiner;


public class CustomOAuth2AuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException {

        HttpStatus status = HttpStatus.UNAUTHORIZED;
        String errorMessage = "Invalid authorization" ;
        Map<String, String> parameters = new LinkedHashMap<>();

        if(request.getHeader("Authorization") == null){
            errorMessage = "Authorization missing";
        }

        if (e instanceof OAuth2AuthenticationException) {
            OAuth2Error error = ((OAuth2AuthenticationException) e).getError();
            parameters.put("error", error.getErrorCode());

            if (StringUtils.hasText(error.getDescription())) {
                parameters.put("error_description", errorMessage);
            }

            if (StringUtils.hasText(error.getUri())) {
                parameters.put("error_uri", error.getUri());
            }

            if (error instanceof BearerTokenError bearerTokenError) {
                if (StringUtils.hasText(bearerTokenError.getScope())) {
                    parameters.put("scope", bearerTokenError.getScope());
                }
                errorMessage = "Invalid token";
                status = ((BearerTokenError) error).getHttpStatus();
            }
        }

        String wwwAuthenticate = computeWWWAuthenticateHeaderValue(parameters);
        response.addHeader("WWW-Authenticate", wwwAuthenticate);
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(new Gson().toJson(new GenericResponse<>(false, errorMessage, null)));
    }


    public static String computeWWWAuthenticateHeaderValue(Map<String, String> parameters) {
        StringJoiner wwwAuthenticate = new StringJoiner(", ", "Bearer ", "");
        if (!parameters.isEmpty()) {
            parameters.forEach((k, v) -> wwwAuthenticate.add(k + "=\"" + v + "\""));
        }
        return wwwAuthenticate.toString();
    }

}

