package com.app.user_manage.component;

import java.io.IOException;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.app.user_manage.service.JwtService;
import com.app.user_manage.service.UserService;

import io.micrometer.common.util.StringUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtUtils extends OncePerRequestFilter{
    
    private final JwtService jwtService;
    private final UserService userService;

    protected void doFilterInternal(
			@NonNull HttpServletRequest request, 
            @NonNull HttpServletResponse response, 
            @NonNull FilterChain filterChain)
			throws ServletException, IOException{
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;
        
        if(StringUtils.isEmpty(authHeader)
                || !org.apache.commons.lang3.StringUtils.startsWith(authHeader, "Bearer")){
                    filterChain.doFilter(request, response);

                    return;
        }

        jwt = authHeader.substring(7);
        username = jwtService.extractUsername(jwt);

        if(StringUtils.isNotEmpty(username) && SecurityContextHolder
            .getContext().getAuthentication() == null){
            UserDetails userDetails = userService.loadUserByUsername(username);
            if(jwtService.isTokenValid(jwt, userDetails)){
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                securityContext.setAuthentication(token);
                SecurityContextHolder.setContext(securityContext);
            }
        }
        filterChain.doFilter(request, response);
    }
}
