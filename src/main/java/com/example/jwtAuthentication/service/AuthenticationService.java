package com.example.jwtAuthentication.service;

import com.example.jwtAuthentication.model.RefreshToken;
import com.example.jwtAuthentication.model.User;
import com.example.jwtAuthentication.repository.UserRepository;
import com.example.jwtAuthentication.util.AuthenticationRequest;
import com.example.jwtAuthentication.util.AuthenticationResponse;
import com.example.jwtAuthentication.util.RefreshRequest;
import com.example.jwtAuthentication.util.RegisterRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@Slf4j
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final UserDetailsService userDetailsService;

    public AuthenticationService(AuthenticationManager authenticationManager, JwtService jwtService,
                                 UserRepository userRepository,
                                 PasswordEncoder passwordEncoder,
                                 RefreshTokenService refreshTokenService,
                                 UserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenService = refreshTokenService;
        this.userDetailsService = userDetailsService;
    }


    /**
     * Register an user in database from incoming request
     * @param request contains username, login and firstName to register a new user
     * @return New Jwt Token for the registered user in response body
     */
    public AuthenticationResponse register(RegisterRequest request){
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalStateException("User already exists, please authenticate"); //checks if username already taken
        }
        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .fullName(request.getFullName())
                .roles(Set.of("ROLE_USER"))
                .build();
        User savedUser = userRepository.save(user); //todo remove variable so we dont use memory while scaling by making a new variable as we only need username while making jwt
        String jwtToken = jwtService.generateJwtToken(savedUser);
        RefreshToken refreshToken = refreshTokenService.generateRefreshToken(savedUser);
        log.info("User {} registered successfully", user.getUsername());
        return AuthenticationResponse.builder()
                .jwtToken(jwtToken)
                .refreshToken(refreshToken.getToken()) //todo decode token
                .build();
    }


    /**
     * Logs in an User from incoming username and password. Filter is ran automatically that verifies jwt
     * @param request contains username and password to authenticate
     * @return New Jwt Token for the registered user in response body
     */
    public AuthenticationResponse authenticate(AuthenticationRequest request){
        var authenticationResponse = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())); // constructor used for un-authenticated requests without roles. If one of the AuthenticationProviders successfully authenticates the user, the AuthenticationManager (via ProviderManager) returns an authenticated Authentication object (full token with roles) //todo add try catch and then controller advice
        User user = (User) authenticationResponse.getPrincipal(); // principal returns an object which is of type UserDetails, could have used UserRepo or userDetailService as well.
        String jwtToken = jwtService.generateJwtToken(user);
        RefreshToken refreshToken = refreshTokenService.generateRefreshToken(user);
        log.info("User {} authenticated successfully", user.getUsername());
        return AuthenticationResponse.builder()
                .jwtToken(jwtToken)
                .refreshToken(refreshToken.getToken()) //todo decode token
                .build();
    }


    /**
     * Endpoint to get a new pair of tokens
     * @param request Contains JWT and refresh token.
     * @return New JWT and refresh token.
     */
    public AuthenticationResponse refresh(RefreshRequest request){
        String jwtToken = request.getJwtToken();
        String refreshToken = request.getRefreshToken();
        User user = (User) userDetailsService.loadUserByUsername(jwtService.extractUsername(jwtToken));
        if(jwtService.isJwtTokenValid(jwtToken, user)){ //first it checks if incoming jwt is still working. If yes it returns same tokens, before this once per request jwtFilter is invoked and it will validte jwt is worked fine. //todo take custom jwt from cookies and dont add in filter logic, or just white list this method from filter (works without this too)
            return AuthenticationResponse.builder() //return same tokens if access token still working
                    .jwtToken(jwtToken)
                    .refreshToken(refreshToken)
                    .build();
        }
        RefreshToken validRefreshTokenObject = refreshTokenService.validateRefreshToken(refreshToken); //checks if refresh token is validated by database and expiry
        String newAccessToken = jwtService.generateJwtToken(user);
        RefreshToken newRefreshToken = refreshTokenService.updateRefreshToken(validRefreshTokenObject); //todo add logging to every method
        return AuthenticationResponse.builder()
                .jwtToken(newAccessToken)
                .refreshToken(newRefreshToken.getToken())
                .build();
    }


    /**
     * Logs out a user by deleting their refresh token.
     */
    public void logout(User user){
        refreshTokenService.deleteByUser(user);
    }
}
