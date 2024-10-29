package com.cursos.api.spring_security_course.persistence.util;

import java.util.Arrays;
import java.util.List;

public enum RoleEnum {

    ADMINISTRATOR(Arrays.asList(
            RolePermissionEnum.READ_ALL_PRODUCTS,
            RolePermissionEnum.READ_ONE_PRODUCT,
            RolePermissionEnum.CREATE_ONE_PRODUCT,
            RolePermissionEnum.UPDATE_ONE_PRODUCT,
            RolePermissionEnum.DISABLE_ONE_PRODUCT,

            RolePermissionEnum.READ_ALL_CATEGORIES,
            RolePermissionEnum.READ_ONE_CATEGORY,
            RolePermissionEnum.CREATE_ONE_CATEGORY,
            RolePermissionEnum.UPDATE_ONE_CATEGORY,
            RolePermissionEnum.DISABLE_ONE_CATEGORY,

            RolePermissionEnum.READ_MY_PROFILE

    )),
    ASSISTANT(Arrays.asList(
            RolePermissionEnum.READ_ALL_PRODUCTS,
                   RolePermissionEnum.READ_ONE_PRODUCT,
                   RolePermissionEnum.UPDATE_ONE_PRODUCT,

                   RolePermissionEnum.READ_ALL_CATEGORIES,
                   RolePermissionEnum.READ_ONE_CATEGORY,
                   RolePermissionEnum.UPDATE_ONE_CATEGORY,

                   RolePermissionEnum.READ_MY_PROFILE
    )),
    CUSTOMER(Arrays.asList(
            RolePermissionEnum.READ_MY_PROFILE
    ));

    private List<RolePermissionEnum> rolePermissionEnums;

    public List<RolePermissionEnum> getRolePermissions() {
        return rolePermissionEnums;
    }

    public void setRolePermissions(List<RolePermissionEnum> rolePermissionEnums) {
        this.rolePermissionEnums = rolePermissionEnums;
    }

    RoleEnum(List<RolePermissionEnum> rolePermissionEnums) {
        this.rolePermissionEnums = rolePermissionEnums;
    }
}
