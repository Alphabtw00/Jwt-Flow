package com.example.jwtAuthentication.repository;

import com.example.jwtAuthentication.model.RefreshToken;
import com.example.jwtAuthentication.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findRefreshTokenByTokenEquals(String refreshToken);
    void deleteByTokenEquals(String refreshToken);

    void deleteByUserEquals (User user);
}
