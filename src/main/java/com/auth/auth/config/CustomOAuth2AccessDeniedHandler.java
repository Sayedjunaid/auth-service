package com.auth.auth.config;

import com.auth.auth.model.GenericResponse;
import com.nimbusds.jose.shaded.gson.Gson;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.web.access.AccessDeniedHandler;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;


public class CustomOAuth2AccessDeniedHandler implements AccessDeniedHandler {

    private String realmName;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException {

        String errorMessage = e.getLocalizedMessage();
        Map<String, String> parameters = new LinkedHashMap<>();


        if (request.getUserPrincipal() instanceof AbstractOAuth2TokenAuthenticationToken) {
            errorMessage = "The request requires higher privileges than provided by the access token.";

            parameters.put("error", "insufficient_scope");
            parameters.put("error_description", errorMessage);
            parameters.put("error_uri", "https://tools.ietf.org/html/rfc6750#section-3.1");
        }

        String wwwAuthenticate = CustomOAuth2AuthenticationEntryPoint.computeWWWAuthenticateHeaderValue(parameters);
        response.addHeader("WWW-Authenticate", wwwAuthenticate);
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(new Gson().toJson(new GenericResponse<>(false, errorMessage, null)));
    }

}
