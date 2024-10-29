package com.cursos.api.spring_security_course.controller;

import com.cursos.api.spring_security_course.dto.SaveProduct;
import com.cursos.api.spring_security_course.persistence.entity.Product;
import com.cursos.api.spring_security_course.service.ProductService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

//@CrossOrigin
@RestController
@RequestMapping("/products")
public class ProductController {

    @Autowired
    private ProductService productService;

    @PreAuthorize("hasAnyRole('ADMINISTRATOR', 'ASSISTANT')")
    @GetMapping
    public ResponseEntity<Page<Product>> findAll(Pageable pageable) {
        Page<Product> productsPage = productService.findAll(pageable);

        if (productsPage.hasContent()) {
            return ResponseEntity.ok(productsPage);
        }

        return ResponseEntity.notFound().build();
    }

    @PreAuthorize("hasAnyRole('ADMINISTRATOR', 'ASSISTANT')")
    @GetMapping("/{productId}")
    public ResponseEntity<Product> findOneById(@PathVariable Long productId) {

        Optional<Product> product = productService.findOneById(productId);

        if (product.isPresent()) {
            return ResponseEntity.ok(product.get());
        }
        return ResponseEntity.notFound().build();
    }

    @PreAuthorize("hasRole('ADMINISTRATOR')")
    @PostMapping()
    public ResponseEntity<Product> createOne(@RequestBody @Valid SaveProduct saveProduct) {

        Product product = productService.createOne(saveProduct);

        return ResponseEntity.status(HttpStatus.CREATED).body(product);
    }

    @PreAuthorize("hasAnyRole('ADMINISTRATOR', 'ASSISTANT')")
    @PutMapping("/{productId}")
    public ResponseEntity<Product> updateOneById(@PathVariable Long productId,
                                                 @RequestBody @Valid SaveProduct saveProduct) {

        Product product = productService.updateOneById(productId, saveProduct);

        return ResponseEntity.ok(product);
    }

    @PreAuthorize("hasRole('ADMINISTRATOR')")
    @PutMapping("/{productId}/disabled")
    public ResponseEntity<Product> disableOneById(@PathVariable Long productId) {

        Product product = productService.disableOneById(productId);

        return ResponseEntity.ok(product);
    }
}
