package com.cursos.api.spring_security_course.controller;

import com.cursos.api.spring_security_course.dto.auth.AuthenticationResponse;
import com.cursos.api.spring_security_course.dto.auth.AuthenticationRequest;
import com.cursos.api.spring_security_course.persistence.entity.User;
import com.cursos.api.spring_security_course.service.auth.AuthenticationService;
import jakarta.validation.Valid;
import org.apache.coyote.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    @Autowired
    private AuthenticationService authenticationService;

    @GetMapping("/validate-token")
    public ResponseEntity<Boolean> validate(@RequestParam String jwt ){

        boolean inTokenValid = authenticationService.validateToken(jwt);
        return ResponseEntity.ok(inTokenValid);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody @Valid AuthenticationRequest authenticationRequest){

        AuthenticationResponse rsp = authenticationService.login(authenticationRequest);
        return ResponseEntity.ok(rsp);

    }

    @GetMapping("/profile")
    public ResponseEntity<User> findMyProfile(){
        User user = authenticationService.findLoggedInUser();
        return ResponseEntity.ok(user);

    }
}
