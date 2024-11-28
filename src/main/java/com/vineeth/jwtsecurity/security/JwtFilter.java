package com.vineeth.jwtsecurity.security;

import com.vineeth.jwtsecurity.utility.JwtUtility;
import io.micrometer.observation.GlobalObservationConvention;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtility jwtUtility;

    private final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("Entering the filter");
        String path = request.getRequestURI();
        if (path != null && (path.startsWith("/auth") || path.startsWith("/access"))) {
            filterChain.doFilter(request, response);
        }else{
            String authHeader = request.getHeader("Authorization");
            if(!authHeader.isEmpty()){
                try{
                    String token = authHeader.substring(7);
                    if(jwtUtility.isValidToken(token)){
                        logger.info("Token Validation Successfully");
                    }
                }catch (Exception ex){
                    logger.error("Token validation failed: {}", ex.getMessage());
                }
            }else{
                logger.info("Invalid Header");
            }
        }
        filterChain.doFilter(request,response);
    }
}
