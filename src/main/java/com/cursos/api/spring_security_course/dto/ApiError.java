package com.cursos.api.spring_security_course.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.time.LocalDateTime;

@Getter
@Setter
public class ApiError implements Serializable {

    private String backendMessage;
    private String message;
    private String url;
    private String method;

    @JsonFormat(pattern = "yyy/MM/dd HH:mm:ss")
    private LocalDateTime timestamp;


}
