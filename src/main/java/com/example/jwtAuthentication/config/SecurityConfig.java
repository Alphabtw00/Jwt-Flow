package com.example.jwtAuthentication.config;

import com.example.jwtAuthentication.filter.JwtAuthenticationFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationManager authenticationManager;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter, AuthenticationManager authenticationManager) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.authenticationManager = authenticationManager;
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
                .authenticationManager(authenticationManager) //sets the custom authentication Manager we made as a bean in Spring Security
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class); // adds custom jwt filter in the filter chain before the basic user/password filter

        return http.build();
    }
}

