package com.dmitrysulman.auth.util;

import com.dmitrysulman.auth.model.User;
import com.dmitrysulman.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

@Component
public class UserValidator implements Validator {
    private final UserService userService;

    @Autowired
    public UserValidator(UserService userService) {
        this.userService = userService;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return User.class.isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        User user = (User) target;
        Long sameUserId = userService.findIdByUsername(user.getUsername());
        if (sameUserId != null && !sameUserId.equals(user.getId())) {
            errors.rejectValue("username", null, "This username is already taken");
        }
    }
}
