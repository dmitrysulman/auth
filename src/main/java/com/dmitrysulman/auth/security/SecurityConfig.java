package com.dmitrysulman.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

@EnableWebSecurity
public class SecurityConfig {

    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final AuthenticationFailureHandler authenticationFailureHandler;
    private final ObjectMapper objectMapper;
    private final UserDetailsService userDetailsService;

    @Autowired
    public SecurityConfig(AuthenticationSuccessHandler authenticationSuccessHandler,
                          AuthenticationFailureHandler authenticationFailureHandler,
                          ObjectMapper objectMapper,
                          UserDetailsService userDetailsService) {
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.authenticationFailureHandler = authenticationFailureHandler;
        this.objectMapper = objectMapper;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        JsonUsernamePasswordAuthenticationFilter jsonUsernamePasswordAuthenticationFilter =
                new JsonUsernamePasswordAuthenticationFilter(
                        "/auth",
                        authenticationSuccessHandler,
                        authenticationFailureHandler,
                        objectMapper);
        http
                .csrf(AbstractHttpConfigurer::disable)
                .exceptionHandling(exceptionHandling ->
                        exceptionHandling.authenticationEntryPoint(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeRequests(authorizeRequests -> authorizeRequests
                        .mvcMatchers("/signup", "/auth")
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                .addFilterAfter(jsonUsernamePasswordAuthenticationFilter,
                        BearerTokenAuthenticationFilter.class)
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .userDetailsService(userDetailsService);

        DefaultSecurityFilterChain filterChain = http.build();
        jsonUsernamePasswordAuthenticationFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));

        return filterChain;
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
