package com.cursos.api.spring_security_course.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.io.Serializable;

public class SaveUser implements Serializable {

    @Size(min = 4)
    private String name;

    @NotBlank
    private String username;

    @Size(min = 8)
    private String password;

    @Size(min = 8)
    private String repeatedPassword;

    public @Size(min = 4) String getName() {
        return name;
    }

    public void setName(@Size(min = 4) String name) {
        this.name = name;
    }


    public @NotBlank String getUsername() {
        return username;
    }

    public void setUsername(@NotBlank String username) {
        this.username = username;
    }

    public @Size(min = 8) String getPassword() {
        return password;
    }

    public void setPassword(@Size(min = 8) String password) {
        this.password = password;
    }

    public @Size(min = 8) String getRepeatedPassword() {
        return repeatedPassword;
    }

    public void setRepeatedPassword(@Size(min = 8) String repeatedPassword) {
        this.repeatedPassword = repeatedPassword;
    }

}
