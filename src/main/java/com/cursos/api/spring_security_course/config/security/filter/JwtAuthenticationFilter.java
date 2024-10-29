package com.cursos.api.spring_security_course.config.security.filter;


import com.cursos.api.spring_security_course.persistence.entity.security.JwtToken;
import com.cursos.api.spring_security_course.persistence.repository.security.JwtTokenRepository;
import com.cursos.api.spring_security_course.service.UserService;
import com.cursos.api.spring_security_course.service.auth.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.swing.text.html.Option;
import java.io.IOException;
import java.util.Date;
import java.util.Optional;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserService userService;

    @Autowired
    private JwtTokenRepository jwtRepository;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //1. Obtener encabezado http llamado authorization


        //2. Obtener token JWT desde el encabezado

        String jwt = jwtService.extractJwtFromRequest(request);

        if(jwt == null || !StringUtils.hasText(jwt)) {
            filterChain.doFilter(request, response);
            return;
        }


        //2.1 Obtener token no expirado y valido desde base de datos

        Optional<JwtToken>token = jwtRepository.findByToken(jwt);
        boolean isValid = validateToken(token);

        if(!isValid) {
            filterChain.doFilter(request, response);
            return;
        }

        //3. Obtener el subjetc / username desde el token
        //   Esta acción a su vez valida el formato del token, firma y fecha de expiracion

        String username = jwtService.extractUserName(jwt);

        //4. Setear objeto authentication dentro del security context holder

        UserDetails userDetails = userService.findOneByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Username " + username + " not found."));
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                username, null, userDetails.getAuthorities());

        authToken.setDetails(new WebAuthenticationDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authToken);

        //5. Ejecutar el resto de filtros

        filterChain.doFilter(request, response);
    }

    private boolean validateToken(Optional<JwtToken> optionalJwtToken) {

        if(!optionalJwtToken.isPresent()) {
            System.out.println("Token no existe o no fue generado en nuestro sistema");
            return false;
        }
        JwtToken token = optionalJwtToken.get();
        Date now = new Date(System.currentTimeMillis());

        boolean isValid = token.isValid() && token.getExpiration().after(now);

        if(!isValid) {
            System.out.println("Token inválido");
            updateTokenStatus(token);
        }

        return isValid;
    }

    private void updateTokenStatus(JwtToken token) {

        token.setValid(false);
        jwtRepository.save(token);
    }
}
