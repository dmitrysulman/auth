package com.dmitrysulman.auth.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    @GetMapping("/userinfo")
    private String userInfo(@AuthenticationPrincipal Jwt jwt) {
        return jwt.getClaim("sub");
    }
}
