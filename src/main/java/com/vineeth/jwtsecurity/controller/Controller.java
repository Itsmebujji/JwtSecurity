package com.vineeth.jwtsecurity.controller;

import com.vineeth.jwtsecurity.utility.JwtUtility;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;

@RestController
public class Controller {

    @Autowired
    private JwtUtility jwtUtility;

    private final Logger logger = LoggerFactory.getLogger(Controller.class);

    @Value("${spring.security.jwt.secret-key}")
    private String secretKey;

    @GetMapping("/authToken")
    public String getToken(HttpServletRequest request){
        String token = jwtUtility.generateToken(request);
        byte[] s = secretKey.getBytes();
        System.out.println(Arrays.toString(s).length());
        logger.info("Token generated successfully");
        return token;
    }

    @GetMapping("/sayHi")
    public String sayHi(){
        return "Hi Vineeth!";
    }

}
