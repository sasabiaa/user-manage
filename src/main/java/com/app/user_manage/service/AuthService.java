package com.app.user_manage.service;

import org.springframework.stereotype.Service;

import com.app.user_manage.dto.Request.TokenRequest;
import com.app.user_manage.dto.Request.UserRequest;
import com.app.user_manage.dto.Response.JwtResponse;
import com.app.user_manage.model.User;

@Service
public interface AuthService {
    
    User register(UserRequest registerRequest);

    JwtResponse login(UserRequest loginRequest);

    JwtResponse refreshToken(TokenRequest refreshTokenRequest);

    boolean validate(TokenRequest tokenRequest);
    
}
