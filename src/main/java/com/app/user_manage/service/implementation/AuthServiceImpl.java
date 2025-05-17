package com.app.user_manage.service.implementation;

import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.app.user_manage.dto.Request.TokenRequest;
import com.app.user_manage.dto.Request.UserRequest;
import com.app.user_manage.dto.Response.JwtResponse;
import com.app.user_manage.model.Role;
import com.app.user_manage.model.User;
import com.app.user_manage.repository.UserRepository;
import com.app.user_manage.service.AuthService;
import com.app.user_manage.service.JwtService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService{
    
    private static final Logger log = LoggerFactory.getLogger(AuthServiceImpl.class);
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @Override
    public User register(UserRequest registerRequest){
        User existingUser = userRepository.findByUsername(registerRequest.getUsername());
        if(existingUser != null){
            log.error("Username {} already exists", registerRequest.getUsername());
        }

        User user = new User();
        user.setUsername(registerRequest.getUsername());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        user.setRole(Role.USER);

        userRepository.save(user);
        log.info("User {} registered successfully", registerRequest.getUsername());

        return existingUser;
    }

    @Override
    public JwtResponse login(UserRequest loginRequest){
        User user = userRepository.findByUsername(loginRequest.getUsername());

        if(user == null){
            log.error("Username not found: {}", loginRequest.getUsername());
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Username not found");
        }

        if(!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())){
            log.error("Invalid username or password for user: {}", loginRequest.getPassword());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid username or password");
        }

        try{
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    loginRequest.getUsername(), loginRequest.getPassword()));

            log.info("Authentication successfully for user: {}", loginRequest.getUsername());
        } catch (AuthenticationException e){
            log.error("Authentication failed for user: {}", loginRequest.getUsername());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "authetication Failed");
        }

        String token = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);

        JwtResponse jwtResponse = new JwtResponse();
        jwtResponse.setToken(token);
        jwtResponse.setRefreshToken(refreshToken);

        return jwtResponse;
    }

    @Override
    public JwtResponse refreshToken(TokenRequest refreshTokenRequest){
        String username = jwtService.extractUsername(refreshTokenRequest.getToken());

        User user = userRepository.findByUsername(username);
        if (user == null){
            log.error("Username not found");
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found");
        }

        if(jwtService.isTokenValid(refreshTokenRequest.getToken(), user)){
            var token = jwtService.generateToken(user);
            log.info("New token generated for user: {}", username);

            var jwtResponse = new JwtResponse();
            jwtResponse.setToken(token);
            jwtResponse.setRefreshToken(refreshTokenRequest.getToken());

            return jwtResponse;
        }

        log.error("Invalid refresh token for user: {}", username);
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token");
    }

    @Override
    public boolean validate(TokenRequest tokenRequest){
        String username = jwtService.extractUsername(tokenRequest.getToken());

        User user = userRepository.findByUsername(username);
        if (user == null){
            log.error("Invalid token, user not found");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token");
        }

        if(jwtService.isTokenValid(tokenRequest.getToken(), user)){
            log.info("Token is valid for user: {}", username);
            return true;
        }

        log.error("Token is invalid for user: {}", username);
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token");
    } 
}
