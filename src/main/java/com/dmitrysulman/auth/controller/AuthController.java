package com.dmitrysulman.auth.controller;

import com.dmitrysulman.auth.model.User;
import com.dmitrysulman.auth.security.JwtAuthenticationSuccessHandler;
import com.dmitrysulman.auth.service.UserService;
import com.dmitrysulman.auth.util.UserValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;

@RestController
public class AuthController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final UserValidator userValidator;
    private final JwtAuthenticationSuccessHandler jwtAuthenticationSuccessHandler;

    @InitBinder("user")
    public void initBinder(WebDataBinder binder) {
        binder.addValidators(userValidator);
    }

    @Autowired
    public AuthController(UserService userService,
                          PasswordEncoder passwordEncoder,
                          UserValidator userValidator,
                          JwtAuthenticationSuccessHandler jwtAuthenticationSuccessHandler) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.userValidator = userValidator;
        this.jwtAuthenticationSuccessHandler = jwtAuthenticationSuccessHandler;
    }

    @PostMapping("/signup")
    private String signup(@RequestBody @Valid User user,
                                              HttpServletRequest request,
                                              HttpServletResponse response) throws ServletException, IOException {
        String password = user.getPassword();
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userService.save(user);
        request.login(user.getUsername(), password);
        response.setStatus(HttpServletResponse.SC_CREATED);
        jwtAuthenticationSuccessHandler.onAuthenticationSuccess(request,
                response,
                SecurityContextHolder.getContext().getAuthentication());
        return null;
    }
}
