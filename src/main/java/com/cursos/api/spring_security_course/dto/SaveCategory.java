package com.cursos.api.spring_security_course.dto;

import jakarta.validation.constraints.NotBlank;

import java.io.Serializable;

public class SaveCategory implements Serializable {

    @NotBlank
    private String name;

    public @NotBlank String getName() {
        return name;
    }

    public void setName(@NotBlank String name) {
        this.name = name;
    }
}
