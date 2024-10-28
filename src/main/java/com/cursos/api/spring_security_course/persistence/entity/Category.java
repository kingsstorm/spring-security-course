package com.cursos.api.spring_security_course.persistence.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class Category {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;

    @NotBlank
    private String name;

    @Enumerated(EnumType.STRING)
    private CategoryStatus status;


    public static enum CategoryStatus {
        ENABLED, DISABLED;
    }
}
