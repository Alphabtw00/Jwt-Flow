package com.example.jwtAuthentication.filter;

import com.example.jwtAuthentication.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


/**
 * OncePerRequestFilter is a type of filter that is executed only once per request
 */
@Component
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }


    /**
     * Jwt filer that works once per request at the start.
     * If jwt is present, it validates it with user stored in database and then set it as the current authentication
     */
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        String jwtToken;
        String username;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) { //if no auth header present, it ends this filter
            filterChain.doFilter(request, response);
            return;
        }

        jwtToken = authHeader.substring(7);
        username = jwtService.extractUsername(jwtToken);

        if(username!=null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = userDetailsService.loadUserByUsername(username); // userDetails stored in database
            if(jwtService.isJwtTokenValid(jwtToken, userDetails)){

                // makes a new UserPasswordToken which is of type Authentication
                // This constructor is used ot create a fully authenticated user so dont use it for initial login requests. Use auth manager for those type of requests.
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities()); // Credentials set as null as this is a token for already authenticated user. Null credentials help securing as we dont want them remaining in context for too long. Use credentials only if password has been changed.
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); // Calls authentication.getDetails and build object from it. These details contain extra information about request like IP address, certificate serial number etc. WebAuthenticationDetailSource is an implementation of AuthenticationDetailsSource which allows getting details from web HTTP request.
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }

}
