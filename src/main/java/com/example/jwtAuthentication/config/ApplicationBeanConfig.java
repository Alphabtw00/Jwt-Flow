package com.example.jwtAuthentication.config;

import com.example.jwtAuthentication.model.User;
import com.example.jwtAuthentication.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

@Configuration
@Slf4j
public class ApplicationBeanConfig {

    private final UserRepository userRepository;

    public ApplicationBeanConfig(UserRepository userRepository) {
        this.userRepository = userRepository;
    }


    /**
     * Password Encoder bean accessible everywhere via auto wiring
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    /**
     * UserDetailService Functional Interface implemented as lambda exposed as a bean accessible everywhere via auto wiring. <br>
     * Used by DaoAuthenticationProvider to fetch UserDetails object from Database
     */
    @Bean
    public UserDetailsService userDetailsService(){
        return username -> {
            Optional<User> user = userRepository.findUserByUsernameEquals(username);
            if(user.isPresent()){
                log.info("user found : {}", user);
                return user.get();
            }
            log.info("user not found for username: {}", username);
            throw new UsernameNotFoundException("User with username \"" + username + "\" not found");
        };
    }


    /**
     * Custom Authentication Manager bean for custom login in controller, only needed if making custom UserPasswordAuthenticationToken and manually setting the authentication
     */
    @Bean
    public AuthenticationManager authenticationManager() throws Exception { // AuthManager is the one that handles authentication. ProviderManager is the default implementation of AuthenticationManager. HttpBasic does this automatically.
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider(); // type of authentication provider that does certain kind of authentication (gets username/password from UserDetailService). Spring makes this authentication manager with dao provider by default. Use AuthenticationConfiguration config, config.getAuthenticationManager() to get default AuthenticationManager used by spring security which auto wires our beans like password encrypter and userDetailService. Use this when customizing the auth manager.
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        authenticationProvider.setUserDetailsService(userDetailsService()); // we can use AuthenticationConfiguration config
        return new ProviderManager(authenticationProvider); //The AuthenticationManager (typically ProviderManager) goes through the authentication filters (e.g., DaoAuthenticationProvider) to check if the credentials are valid.
    }
}
