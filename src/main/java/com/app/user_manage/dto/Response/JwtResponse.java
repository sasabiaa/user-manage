package com.app.user_manage.dto.Response;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JwtResponse {

    private String token;
    
    private String refreshToken;

}
