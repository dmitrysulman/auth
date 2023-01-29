package com.dmitrysulman.auth.security;

import com.dmitrysulman.auth.dto.CredentialsDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;

public class JsonUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final ObjectMapper objectMapper;
    private String username;
    private String password;

    public JsonUsernamePasswordAuthenticationFilter(AuthenticationSuccessHandler successHandler,
                                                    AuthenticationFailureHandler failureHandler,
                                                    AuthenticationManager authenticationManager,
                                                    ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/auth", "POST"));
        setAuthenticationSuccessHandler(successHandler);
        setAuthenticationFailureHandler(failureHandler);
        setAuthenticationManager(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        parseJsonBody(request);
        return super.attemptAuthentication(request, response);
    }

    @Override
    protected String obtainPassword(HttpServletRequest request) {
        return password;
    }

    @Override
    protected String obtainUsername(HttpServletRequest request) {
        return username;
    }

    private void parseJsonBody(HttpServletRequest request) {
        try {
            BufferedReader reader = request.getReader();
            StringBuilder body = new StringBuilder();
            String line = reader.readLine();
            while (line != null) {
                body.append(line);
                line = reader.readLine();
            }
            CredentialsDto credentials = objectMapper.readValue(body.toString(), CredentialsDto.class);
            username = credentials.username();
            password = credentials.password();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
