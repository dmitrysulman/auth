package com.dmitrysulman.auth.model;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Entity
@Table(name = "users")
@Getter
@Setter
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "username", unique = true)
    @NotBlank
    @Size(min = 3, max = 20)
    private String username;

    @Column(name = "password")
    @NotBlank
    @Size(min = 3, max = 512)
    private String password;
}
