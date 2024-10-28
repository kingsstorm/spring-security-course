package com.cursos.api.spring_security_course.config.security;

import com.cursos.api.spring_security_course.config.security.filter.JwtAuthenticationFilter;
import com.cursos.api.spring_security_course.persistence.util.Role;
import com.cursos.api.spring_security_course.persistence.util.RolePermission;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class HttpSecurityConfig {

    @Autowired
    private AuthenticationProvider daoAuthProvider;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        SecurityFilterChain filterChain =  http.csrf(csrfConfig -> csrfConfig.disable())
                .sessionManagement(sessMagConfig -> sessMagConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(daoAuthProvider)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(authReqConfig -> {

                    buildRequestMatchersRoles(authReqConfig);
                })
                .build();

        return filterChain;
    }

    /**
     * Ejemplo con authorities
     * @param authReqConfig
     */
    private static void buildRequestMatchersAuthorities(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authReqConfig) {
    /*
    Autorizacion de endpoints de productos
     */
        authReqConfig.requestMatchers(HttpMethod.GET, "/products")
                .hasAuthority(RolePermission.READ_ALL_PRODUCTS.name());

        authReqConfig.requestMatchers(HttpMethod.GET, "/products/{productId}")
                .hasAuthority(RolePermission.READ_ONE_PRODUCT.name());

        authReqConfig.requestMatchers(HttpMethod.POST, "/products")
                .hasAuthority(RolePermission.CREATE_ONE_PRODUCT.name());

        authReqConfig.requestMatchers(HttpMethod.PUT, "/products/{productId}")
                .hasAuthority(RolePermission.UPDATE_ONE_PRODUCT.name());

        authReqConfig.requestMatchers(HttpMethod.PUT, "/products/{productId}/disabled")
                .hasAuthority(RolePermission.DISABLE_ONE_PRODUCT.name());

        // ----------------------------------------------------------------------------------
                    /*
                    Autorizacion de endpoints de categorias
                     */
        authReqConfig.requestMatchers(HttpMethod.GET, "/categories")
                .hasAuthority(RolePermission.READ_ALL_CATEGORIES.name());

        authReqConfig.requestMatchers(HttpMethod.GET, "/categories/{categoryId}")
                .hasAuthority(RolePermission.READ_ONE_CATEGORY.name());

        authReqConfig.requestMatchers(HttpMethod.POST, "/categories")
                .hasAuthority(RolePermission.CREATE_ONE_CATEGORY.name());

        authReqConfig.requestMatchers(HttpMethod.PUT, "/categories/{categoryId}")
                .hasAuthority(RolePermission.UPDATE_ONE_CATEGORY.name());

        authReqConfig.requestMatchers(HttpMethod.GET, "/categories/profile")
                .hasAuthority(RolePermission.READ_MY_PROFILE.name());

        authReqConfig.requestMatchers(HttpMethod.PUT, "/aujth/{categoryId}/disabled")
                .hasAuthority(RolePermission.DISABLE_ONE_CATEGORY.name());

                    /*
                    Autorizacion de endpoints publicos
                     */

        authReqConfig.requestMatchers(HttpMethod.POST, "/customers").permitAll();
        authReqConfig.requestMatchers(HttpMethod.POST, "/auth/authenticate").permitAll();
        authReqConfig.requestMatchers(HttpMethod.GET, "/auth/validate-token").permitAll();
        authReqConfig.anyRequest().authenticated();
    }

    /**
     * Ejemplo con roles
     * @param authReqConfig
     */
    private static void buildRequestMatchersRoles(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authReqConfig) {
    /*
    Autorizacion de endpoints de productos
     */
        authReqConfig.requestMatchers(HttpMethod.GET, "/products")
                .hasAnyRole(Role.ADMINISTRATOR.name(), Role.ASSISTANT.name());

        authReqConfig.requestMatchers(HttpMethod.GET, "/products/{productId}")
                .hasAnyRole(Role.ADMINISTRATOR.name(), Role.ASSISTANT.name());

        authReqConfig.requestMatchers(HttpMethod.POST, "/products")
                .hasRole(Role.ADMINISTRATOR.name());

        authReqConfig.requestMatchers(HttpMethod.PUT, "/products/{productId}")
                .hasAnyRole(Role.ADMINISTRATOR.name(), Role.ASSISTANT.name());

        authReqConfig.requestMatchers(HttpMethod.PUT, "/products/{productId}/disabled")
                        .hasRole(Role.ADMINISTRATOR.name());

        // ----------------------------------------------------------------------------------
                    /*
                    Autorizacion de endpoints de categorias
                     */
        authReqConfig.requestMatchers(HttpMethod.GET, "/categories")
                .hasAnyRole(Role.ADMINISTRATOR.name(), Role.ASSISTANT.name());

        authReqConfig.requestMatchers(HttpMethod.GET, "/categories/{categoryId}")
                .hasAnyRole(Role.ADMINISTRATOR.name(), Role.ASSISTANT.name());

        authReqConfig.requestMatchers(HttpMethod.POST, "/categories")
                .hasRole(Role.ADMINISTRATOR.name());

        authReqConfig.requestMatchers(HttpMethod.PUT, "/categories/{categoryId}")
                .hasAnyRole(Role.ADMINISTRATOR.name(), Role.ASSISTANT.name());

        authReqConfig.requestMatchers(HttpMethod.PUT, "/aujth/{categoryId}/disabled")
                .hasRole(Role.ADMINISTRATOR.name());

        authReqConfig.requestMatchers(HttpMethod.GET, "/categories/profile")
                .hasAnyRole(Role.ADMINISTRATOR.name(), Role.ASSISTANT.name(), Role.CUSTOMER.name());

                    /*
                    Autorizacion de endpoints publicos
                     */

        authReqConfig.requestMatchers(HttpMethod.POST, "/customers").permitAll();
        authReqConfig.requestMatchers(HttpMethod.POST, "/auth/authenticate").permitAll();
        authReqConfig.requestMatchers(HttpMethod.GET, "/auth/validate-token").permitAll();
        authReqConfig.anyRequest().authenticated();
    }
}
