package com.cursos.api.spring_security_course.dto;


import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

import java.io.Serializable;
import java.math.BigDecimal;

public class SaveProduct implements Serializable {

    private String name;
    private BigDecimal price;
    private long categoryId;

    @NotBlank
    public String getName() {
        return name;
    }

    @DecimalMin(value = "0.01")
    public BigDecimal getPrice() {
        return price;
    }

    @Min(value = 1)
    public long getCategoryId() {
        return categoryId;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setPrice(BigDecimal price) {
        this.price = price;
    }

    public void setCategoryId(long categoryId) {
        this.categoryId = categoryId;
    }
}
