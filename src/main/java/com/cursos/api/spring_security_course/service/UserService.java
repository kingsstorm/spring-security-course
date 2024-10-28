package com.cursos.api.spring_security_course.service;

import com.cursos.api.spring_security_course.dto.SaveUser;
import com.cursos.api.spring_security_course.persistence.entity.User;
import jakarta.validation.Valid;

import java.util.Optional;

public interface UserService {
    User registerOneCustomer(@Valid SaveUser newUser);

    Optional<User> findOneByUsername(String username);
}
