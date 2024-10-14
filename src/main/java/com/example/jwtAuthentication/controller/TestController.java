package com.example.jwtAuthentication.controller;

import com.example.jwtAuthentication.jwt.JwtService;
import com.example.jwtAuthentication.model.User;
import com.example.jwtAuthentication.repository.UserRepository;
import com.example.jwtAuthentication.service.AuthenticationService;
import com.example.jwtAuthentication.util.AuthenticationRequest;
import com.example.jwtAuthentication.util.AuthenticationResponse;
import com.example.jwtAuthentication.util.RegisterRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
public class TestController {

    private final AuthenticationService authenticationService;

    public TestController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @GetMapping("/test")
    public ResponseEntity<String> testMethod(@AuthenticationPrincipal User user) {
        return new ResponseEntity<>("Successful", HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request){
        return ResponseEntity.ok(authenticationService.register(request));
    }
}