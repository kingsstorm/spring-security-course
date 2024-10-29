package com.cursos.api.spring_security_course.persistence.entity.security;

import jakarta.persistence.*;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class Operation {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private long id;

    private String name; //FIND_ALL_PRODUCTS.... ETC

    private String path;  // /products/{product}/disabled ejemplo

    private String httpMethod;  // POST, PUT, GET

    private boolean permitAll;

    @ManyToOne
    @JoinColumn(name = "module_id")
    private Module module;



}
