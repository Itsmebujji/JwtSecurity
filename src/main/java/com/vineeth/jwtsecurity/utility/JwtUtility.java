package com.vineeth.jwtsecurity.utility;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtility {

    @Value("${spring.security.jwt.secret-key}")
    private String secretKey;

    private final Logger logger = LoggerFactory.getLogger(JwtUtility.class);

    public boolean isValidToken(String token){
        return validToken(token) && isTokenExpired(token);
    }

    public boolean validToken(String token){

        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        try {
            Jwts.parser().setSigningKey(key)
                    .build()
                    .parseSignedClaims(token);
            return true;
        }catch (Exception ex){
            logger.error("Token validation failed: {}", ex.getMessage());
            return false;
        }
    }

    public Claims extractClaims(String token){
        return Jwts.parser().build().parseSignedClaims(token).getPayload();
    }

    public boolean isTokenExpired(String token){
        return expDate(token).after(new Date());
    }

    public Date expDate(String token){
        Claims claims = extractClaims(token);
        return claims.getExpiration();
    }


    public String generateToken(HttpServletRequest request) {
        String username = request.getHeader("name");
        long nowMillis = System.currentTimeMillis();
        long expMillis = nowMillis + 3600000;
        Date exp = new Date(expMillis);
        System.out.println(secretKey);
        return Jwts.builder()
                .subject(username)
                .claim("role","user")
                .issuedAt(new Date(nowMillis))
                .signWith(getSigninKey())
                .expiration(exp)
                .compact();
    }

    public Key getSigninKey(){
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
