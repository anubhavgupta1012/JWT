package com.jwt.controller;

import com.jwt.pojo.AuthenticationRequest;
import com.jwt.pojo.AuthenticationResponse;
import com.jwt.pojo.CustomUserDetails;
import com.jwt.service.JWTService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {
    Logger logger = LoggerFactory.getLogger(ResourceController.class);

    @Autowired
    private JWTService jwtService;
    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/data")
    public String getData() {
        return "Highly Secured String";
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> getJWTToken(@RequestBody AuthenticationRequest authenticationRequest) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(),
                authenticationRequest.getPassword()));
        } catch (Exception exception) {
            logger.info("Exception Occured " + exception);
        }
        return ResponseEntity.ok(new AuthenticationResponse(jwtService.generateToken(new CustomUserDetails(authenticationRequest.getUsername(),
            authenticationRequest.getPassword()))));
    }
}
