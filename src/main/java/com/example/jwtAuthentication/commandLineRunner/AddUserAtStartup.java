package com.example.jwtAuthentication.commandLineRunner;

import com.example.jwtAuthentication.model.User;
import com.example.jwtAuthentication.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class AddUserAtStartup implements CommandLineRunner {
    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;

    public AddUserAtStartup(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }


    /**
     * Adds an admin user at application Startup
     */
    @Override
    public void run(String... args) throws Exception {
        User adminUser = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("12345"))
                .fullName("Ansh Anand")
                .roles(Set.of("ROLE_ADMIN", "ROLE_USER"))
                .build();
        userRepository.save(adminUser);
    }
}
