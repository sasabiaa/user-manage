package com.app.user_manage.service;

import java.util.Map;

import org.springframework.security.core.userdetails.UserDetails;


public interface JwtService {

    String generateToken(UserDetails userDetails);

    String generateRefreshToken(Map<String, Object> extraClaims, UserDetails userDetails);

    String extractUsername(String token);

    boolean isTokenValid(String token, UserDetails userDetails);

}
