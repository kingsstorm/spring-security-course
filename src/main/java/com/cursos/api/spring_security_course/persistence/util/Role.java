package com.cursos.api.spring_security_course.persistence.util;

import java.util.Arrays;
import java.util.List;

public enum Role {

    ADMINISTRATOR(Arrays.asList(
            RolePermission.READ_ALL_PRODUCTS,
            RolePermission.READ_ONE_PRODUCT,
            RolePermission.CREATE_ONE_PRODUCT,
            RolePermission.UPDATE_ONE_PRODUCT,
            RolePermission.DISABLE_ONE_PRODUCT,

            RolePermission.READ_ALL_CATEGORIES,
            RolePermission.READ_ONE_CATEGORY,
            RolePermission.CREATE_ONE_CATEGORY,
            RolePermission.UPDATE_ONE_CATEGORY,
            RolePermission.DISABLE_ONE_CATEGORY,

            RolePermission.READ_MY_PROFILE

    )),
    ASSISTANT(Arrays.asList(
            RolePermission.READ_ALL_PRODUCTS,
                   RolePermission.READ_ONE_PRODUCT,
                   RolePermission.UPDATE_ONE_PRODUCT,

                   RolePermission.READ_ALL_CATEGORIES,
                   RolePermission.READ_ONE_CATEGORY,
                   RolePermission.UPDATE_ONE_CATEGORY,

                   RolePermission.READ_MY_PROFILE
    )),
    CUSTOMER(Arrays.asList(
            RolePermission.READ_MY_PROFILE
    ));

    private List<RolePermission> rolePermissions;

    public List<RolePermission> getRolePermissions() {
        return rolePermissions;
    }

    public void setRolePermissions(List<RolePermission> rolePermissions) {
        this.rolePermissions = rolePermissions;
    }

    Role(List<RolePermission> rolePermissions) {
        this.rolePermissions = rolePermissions;
    }
}
