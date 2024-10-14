package com.example.jwtAuthentication.service;

import com.example.jwtAuthentication.jwt.JwtService;
import com.example.jwtAuthentication.model.User;
import com.example.jwtAuthentication.repository.UserRepository;
import com.example.jwtAuthentication.util.AuthenticationRequest;
import com.example.jwtAuthentication.util.AuthenticationResponse;
import com.example.jwtAuthentication.util.RegisterRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthenticationService(AuthenticationManager authenticationManager, JwtService jwtService, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }


    /**
     * Register an user in database from incoming request
     * @return New Jwt Token for the registered user in response body
     */
    public AuthenticationResponse register(RegisterRequest request){
        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .fullName(request.getFullName())
                .roles(Set.of("ROLE_USER"))
                .build();
        User savedUser = userRepository.save(user); //dont use memory while scaling by making a new variable as we only need username while making jwt
        String jwtToken = jwtService.generateJwtToken(savedUser);
        return AuthenticationResponse.builder()
                .jwtToken(jwtToken)
                .build();
    }


    /**
     * Logs in an User from incoming username and password. Filter is ran automatically that verifies jwt
     * @return New Jwt Token for the registered user in response body
     */
    public AuthenticationResponse authenticate(AuthenticationRequest request){
        var authenticationResponse = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())); // constructor used for un-authenticated requests without roles. If one of the AuthenticationProviders successfully authenticates the user, the AuthenticationManager (via ProviderManager) returns an authenticated Authentication object (full token with roles)
        User user = (User) authenticationResponse.getPrincipal(); // principal returns an object which is of type UserDetails, could have used UserRepo or userDetailService as well.
        String jwtToken = jwtService.generateJwtToken(user);
        return AuthenticationResponse.builder()
                .jwtToken(jwtToken)
                .build();
    }
}
