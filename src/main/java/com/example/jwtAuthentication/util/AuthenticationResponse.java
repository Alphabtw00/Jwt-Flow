package com.example.jwtAuthentication.util;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthenticationResponse {
    private String jwtToken;
    private String refreshToken;
}
