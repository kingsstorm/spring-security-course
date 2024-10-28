package com.cursos.api.spring_security_course.service.impl;

import com.cursos.api.spring_security_course.dto.SaveUser;
import com.cursos.api.spring_security_course.exception.InvalidPasswordException;
import com.cursos.api.spring_security_course.persistence.entity.User;
import com.cursos.api.spring_security_course.persistence.repository.UserRepository;
import com.cursos.api.spring_security_course.persistence.util.Role;
import com.cursos.api.spring_security_course.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Override
    public User registerOneCustomer(SaveUser newUser) {

        validatePassword(newUser);

        User user = new User();

        user.setPassword(passwordEncoder.encode(newUser.getPassword()));

        user.setName(newUser.getName());
        user.setUsername(newUser.getUsername());
        user.setRole(Role.CUSTOMER);

        return userRepository.save(user);

    }

    @Override
    public Optional<User> findOneByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    private void validatePassword(SaveUser newUser) {

        if(!StringUtils.hasText(newUser.getPassword()) || !StringUtils.hasText(newUser.getRepeatedPassword())) {
            throw new InvalidPasswordException("Password don't match");
        }

        if(!newUser.getPassword().equals(newUser.getRepeatedPassword())) {
            throw new InvalidPasswordException("Password don't match");
        }


    }
}
