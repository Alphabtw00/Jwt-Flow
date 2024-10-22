package com.example.jwtAuthentication.util;

import lombok.Data;

@Data
public class RefreshRequest {
    private String jwtToken;
    private String refreshToken;
}
