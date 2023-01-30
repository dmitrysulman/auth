package com.dmitrysulman.auth.repository;

import com.dmitrysulman.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    @Query("select u.id from User u where u.username = :username")
    Long findIdByUsername(String username);
}

