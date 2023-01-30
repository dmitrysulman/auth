package com.dmitrysulman.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;

public class JsonAuthenticationConverter implements AuthenticationConverter {
    private final ObjectMapper objectMapper;

    public JsonAuthenticationConverter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public UsernamePasswordAuthenticationToken convert(HttpServletRequest request) {
        try {
            BufferedReader reader = request.getReader();
            StringBuilder body = new StringBuilder();
            String line = reader.readLine();
            while (line != null) {
                body.append(line);
                line = reader.readLine();
            }
            CredentialsRecord credentials = objectMapper.readValue(body.toString(), CredentialsRecord.class);
            String username = credentials.username();
            String password = credentials.password();
            return new UsernamePasswordAuthenticationToken(username, password);
        } catch (IOException e) {
            throw new BadCredentialsException("Bad credentials");
        }
    }
}
