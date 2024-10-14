package com.example.jwtAuthentication.config;

import com.example.jwtAuthentication.jwt.JwtAuthenticationFilter;
import com.example.jwtAuthentication.model.User;
import com.example.jwtAuthentication.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Optional;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig {
    private final UserRepository userRepository;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(UserRepository userRepository, JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.userRepository = userRepository;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }


    /**
     * List of filters thrown on incoming request for security handling
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .headers(httpSecurityHeadersConfigurer ->
                        httpSecurityHeadersConfigurer
                                .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable)) //disable csrf for now

                .authorizeHttpRequests(auth->
                        auth
                                .requestMatchers("/test").hasAnyRole("ADMIN", "USER") //allows user with any of these roles
                                .requestMatchers("/login").permitAll() //allows everyone
                                .anyRequest().permitAll()) //to make h-2 usage easy

                .sessionManagement(session->
                        session
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //jwt is stateless so spring wont create sessions
                .authenticationManager(authenticationManager()) //sets the custom authentication Manager we made in Spring Security
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class); // adds custom jwt filter in the filter chain before the basic user/password filter

        return http.build();
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

