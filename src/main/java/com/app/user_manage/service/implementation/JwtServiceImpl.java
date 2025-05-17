package com.app.user_manage.service.implementation;

import java.util.Date;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.app.user_manage.service.JwtService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtServiceImpl implements JwtService{

    private static final Logger log = LoggerFactory.getLogger(JwtServiceImpl.class);

    @Override
    public String generateToken(UserDetails userDetails){
        log.info("Token generted successfully for username {}", userDetails.getUsername());

        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis()))
                .signWith(getSigningKey())
                .compact();
    }

    @Override
    public String generateRefreshToken(Map<String, Object> extractClaims, UserDetails userDetails){
        log.info("Refresh token generated successfully for user: {}", userDetails.getUsername());

        return Jwts.builder().claims(extractClaims).subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis()))
                .signWith(getSigningKey())
                .compact();
    }

    @Override
    public String extractUsername(String token){
        String username = extractClaims(token, Claims::getSubject);
        log.info("Username extracted: {}", username);

        return username;
    }

    @Override
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        if(isTokenExpired(token)){
            log.error("Token is expired for user {}", userDetails.getUsername());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token has Expired");
        }

        boolean isValid = (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        if(isValid){
            log.info("Token is Valid for user: {}", userDetails.getUsername());
        } else {
            log.error("Token is invalid for user {}", userDetails.getUsername());
        }

        return isValid;
    }

    private SecretKey getSigningKey(){
        byte[] key = Decoders.BASE64.decode("878");

        return Keys.hmacShaKeyFor(key);
    }

    private <T> T extractClaims(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);

        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token){
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build().parseSignedClaims(token)
                .getPayload();
    }

    private boolean isTokenExpired(String token){
        boolean isExpired = extractClaims(token, Claims::getExpiration)
                .before(new Date());

                if(isExpired){
                    log.error("Token is expired");
                } else {
                    log.info("Token is not expired");
                }

                return isExpired;
    }
}
