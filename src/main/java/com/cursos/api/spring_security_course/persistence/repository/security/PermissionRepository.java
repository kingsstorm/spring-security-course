package com.cursos.api.spring_security_course.persistence.repository.security;

import com.cursos.api.spring_security_course.persistence.entity.security.GrantedPermission;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PermissionRepository extends JpaRepository<GrantedPermission, Long> {
}
