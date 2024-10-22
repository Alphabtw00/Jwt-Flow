package com.example.jwtAuthentication.service;

import com.example.jwtAuthentication.model.RefreshToken;
import com.example.jwtAuthentication.model.User;
import com.example.jwtAuthentication.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
public class RefreshTokenService {
    @Value("${refresh.expiry}")
    private Long expiry; //refresh token expiry in days
    private final RefreshTokenRepository refreshTokenRepository;


    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }


    /**
     * Returns a new Refresh token with customised expiry from incoming User object
     */
    public RefreshToken generateRefreshToken(User user) {
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiry(Instant.now().plus(expiry, ChronoUnit.DAYS))
                .build();
        return refreshTokenRepository.save(refreshToken);
    }


    /**
     * Checks expiry for refresh token, deletes if invalid
     */
    public RefreshToken checkTokenExpiry(RefreshToken refreshTokenObject){
        if(refreshTokenObject.getExpiry().isBefore(Instant.now())){
            refreshTokenRepository.delete(refreshTokenObject);
            throw new RuntimeException("Refresh token expired! Please log in again.");
        }
        return refreshTokenObject;
    }


    /**
     * Validates refresh token by checking in database and then validating its expiry
     */
    public RefreshToken validateRefreshToken(String refreshToken){
        return refreshTokenRepository.findRefreshTokenByTokenEquals(refreshToken)
                .map(this::checkTokenExpiry) //if token present it does this
                .orElseThrow(() -> new RuntimeException("Invalid refresh token!")); //throws this is not present (can use extra logic in lambda)
    }


    /**
     * Updates incoming refresh token with a bew token and expiry
     */
    public RefreshToken updateRefreshToken(RefreshToken existingToken) {
        existingToken.setToken(UUID.randomUUID().toString());
        existingToken.setExpiry(Instant.now().plus(expiry, ChronoUnit.DAYS));
        return refreshTokenRepository.save(existingToken);
    }


    /**
     * Delete refresh token from user.
     */
    public void deleteByUser(User user){
        refreshTokenRepository.deleteByUserEquals(user);
    }

}
