package com.dmitrysulman.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class JsonUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final JsonAuthenticationConverter jsonAuthenticationConverter;

    public JsonUsernamePasswordAuthenticationFilter(String loginUrl,
                                                    AuthenticationSuccessHandler successHandler,
                                                    AuthenticationFailureHandler failureHandler,
                                                    ObjectMapper objectMapper) {
        jsonAuthenticationConverter = new JsonAuthenticationConverter(objectMapper);
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher(loginUrl, "POST"));
        setAuthenticationSuccessHandler(successHandler);
        setAuthenticationFailureHandler(failureHandler);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        } else {
            UsernamePasswordAuthenticationToken authRequest = jsonAuthenticationConverter.convert(request);
            this.setDetails(request, authRequest);
            return this.getAuthenticationManager().authenticate(authRequest);
        }
    }
}
