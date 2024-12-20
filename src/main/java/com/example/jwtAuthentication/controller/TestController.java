package com.example.jwtAuthentication.controller;

import com.example.jwtAuthentication.model.User;
import com.example.jwtAuthentication.service.AuthenticationService;
import com.example.jwtAuthentication.util.AuthenticationRequest;
import com.example.jwtAuthentication.util.AuthenticationResponse;
import com.example.jwtAuthentication.util.RefreshRequest;
import com.example.jwtAuthentication.util.RegisterRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    private final AuthenticationService authenticationService;

    public TestController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    
    /**
     * Use this method to test authentication
     */
    @GetMapping("/test")
    public ResponseEntity<String> testMethod(@AuthenticationPrincipal User user) {
        return new ResponseEntity<>("Successful", HttpStatus.OK);
    }


    /**
     * Login method which accepts username and password, returns a Jwt if successfully authenticated
     */
    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> authenticateUser(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }


    /**
     * Register method which accpets username, password and full-name, returns a Jwt after saving a new user in db
     */
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> registerUser(@RequestBody RegisterRequest request){
        //todo add exception handling and logging everywhere in the app
        return ResponseEntity.ok(authenticationService.register(request));
    }



    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponse> refreshToken(@RequestBody RefreshRequest request){
        AuthenticationResponse response = authenticationService.refresh(request);
        return ResponseEntity.ok(response);
    }



   @PostMapping("/logout")
   public ResponseEntity<?> logout(@AuthenticationPrincipal User user){
       authenticationService.logout(user);
       return ResponseEntity.ok("Logged out successfully");
   }

}