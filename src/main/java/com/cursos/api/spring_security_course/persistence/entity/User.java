package com.cursos.api.spring_security_course.persistence.entity;

import com.cursos.api.spring_security_course.persistence.util.Role;
import jakarta.persistence.*;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Entity
@Getter
@Setter
@Table (name = "\"user\"")
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private long id;

    @Column(unique = true)
    private String username;
    private String name;
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;



    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        if (role == null) return null;
        if(role.getRolePermissions() == null) return null;

        List<SimpleGrantedAuthority> auth =  role.getRolePermissions().stream()
                .map(each -> each.name())
                .map(each -> new SimpleGrantedAuthority(each))
//                .map(each -> {
//            String permission = each.name();
//            return new SimpleGrantedAuthority(permission);
//        })
                .collect(Collectors.toList());

        auth.add(new SimpleGrantedAuthority("ROLE_" + this.role.name()));
        return auth;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
