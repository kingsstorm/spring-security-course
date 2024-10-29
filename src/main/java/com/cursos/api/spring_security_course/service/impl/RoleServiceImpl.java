package com.cursos.api.spring_security_course.service.impl;

import com.cursos.api.spring_security_course.persistence.entity.security.Role;
import com.cursos.api.spring_security_course.persistence.repository.security.RoleRepository;
import com.cursos.api.spring_security_course.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class RoleServiceImpl implements RoleService {

    @Value("${security.default.role}")
    private String defaultRole;

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public Optional<Role> findDefaulRole() {
        return roleRepository.findByName(defaultRole);
    }
}
