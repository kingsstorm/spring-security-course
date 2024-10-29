package com.cursos.api.spring_security_course.service.auth;

import com.cursos.api.spring_security_course.dto.RegisteredUser;
import com.cursos.api.spring_security_course.dto.SaveUser;
import com.cursos.api.spring_security_course.dto.auth.AuthenticationRequest;
import com.cursos.api.spring_security_course.dto.auth.AuthenticationResponse;
import com.cursos.api.spring_security_course.persistence.entity.security.JwtToken;
import com.cursos.api.spring_security_course.persistence.entity.security.User;
import com.cursos.api.spring_security_course.persistence.repository.security.JwtTokenRepository;
import com.cursos.api.spring_security_course.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class AuthenticationService {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenRepository jwtRepository;


    public RegisteredUser registerOneCustomer(@Valid SaveUser newUser) {

        User user = userService.registerOneCustomer(newUser);
        String jwt= jwtService.generateToken(user, generateExtraClaims(user));
        saveUserToken(user, jwt);
        RegisteredUser userDto = new RegisteredUser();
        userDto.setId(user.getId());
        userDto.setName(user.getName());
        userDto.setUsername(user.getUsername());
        userDto.setRole(user.getRole().getName());

        userDto.setJwt(jwt);

        return userDto;
    }

    private Map<String, Object> generateExtraClaims(User user) {
        Map<String, Object> extraClaims = new HashMap<>();

        extraClaims.put("name", user.getName());
        extraClaims.put("role", user.getRole().getName());
        extraClaims.put("authorities", user.getAuthorities());

        return extraClaims;
    }

    public AuthenticationResponse login(@Valid AuthenticationRequest authenticationRequest) {

        Authentication authentication = new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword());
        authenticationManager.authenticate(authentication);

        UserDetails user = userService.findOneByUsername(authenticationRequest.getUsername()).get();

        String jwt = jwtService.generateToken(user, generateExtraClaims((User) user));
        saveUserToken((User) user, jwt);

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
        authenticationResponse.setJwt(jwt);

        return authenticationResponse;
    }

    private void saveUserToken(User user, String jwt) {

        JwtToken token = new JwtToken();
        token.setToken(jwt);
        token.setUser(user);
        token.setExpiration(jwtService.extractExpiration(jwt));
        token.setValid(true);
        jwtRepository.save(token);
    }

    public boolean validateToken(String jwt) {

        try {
            jwtService.extractUserName(jwt);
            return true;
        }catch (Exception e){
            System.out.println(e.getMessage());
            return false;
        }
    }

    public User findLoggedInUser() {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth instanceof UsernamePasswordAuthenticationToken authToken) {
            String username = (String) authToken.getPrincipal();

            return userService.findOneByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found. Username: " + username));
        }

        return null;
    }

    public void logout(HttpServletRequest request) {

        String jwt = jwtService.extractJwtFromRequest(request);
        if (jwt == null || !StringUtils.hasText(jwt)) {
            return;
        }

        Optional<JwtToken> token = jwtRepository.findByToken(jwt);

        if(token.isPresent() && token.get().isValid()) {
            token.get().setValid(false);
            jwtRepository.save(token.get());
        }
    }
}
