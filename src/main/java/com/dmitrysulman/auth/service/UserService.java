package com.dmitrysulman.auth.service;

import com.dmitrysulman.auth.model.User;

import java.util.Optional;

public interface UserService {
    Optional<User> findByUsername(String username);

    Long findIdByUsername(String username);

    User save(User user);
}
