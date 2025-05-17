package com.app.user_manage.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.app.user_manage.dto.Request.TokenRequest;
import com.app.user_manage.dto.Request.UserRequest;
import com.app.user_manage.dto.Response.JwtResponse;
import com.app.user_manage.model.User;
import com.app.user_manage.service.AuthService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private final AuthService authService;

    @PostMapping("/Register")
    public ResponseEntity<User> register(@RequestBody UserRequest registerRequest){
        User registeredUser = authService.register(registerRequest);
        log.info("User registered Successfully with username : {}", registerRequest.getUsername());

        return new ResponseEntity<>(registeredUser, HttpStatus.OK);
    }

    @PostMapping("/Login")
    public ResponseEntity<JwtResponse> login(@RequestBody UserRequest loginRequest){
        JwtResponse jwtResponse = authService.login(loginRequest);
        log.info("User logged in successfully with username: {}", loginRequest.getUsername());

        return new ResponseEntity<>(jwtResponse, HttpStatus.OK);
    }

    @PostMapping("/RefreshToken")
    public ResponseEntity<JwtResponse> refresh(@RequestBody TokenRequest refreshToken){
        JwtResponse jwtResponse = authService.refreshToken(refreshToken);
        log.info("Token refreshed successfully");
        return new ResponseEntity<>(jwtResponse, HttpStatus.OK);
    }

    @PostMapping("/validate")
    public ResponseEntity<Boolean> validate(@RequestBody TokenRequest tokenRequest){
        Boolean status = authService.validate(tokenRequest);
        log.info("Token validate status: {}", status);
        return new ResponseEntity<>(status, HttpStatus.OK);
    }
}
