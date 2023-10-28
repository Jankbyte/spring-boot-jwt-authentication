package ru.jankbyte.spring.jwtauth.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.jankbyte.spring.jwtauth.dto.AuthenticationResponse;
import ru.jankbyte.spring.jwtauth.service.TokenService;

@RestController
@RequestMapping(path = {"/api/authentication"},
    consumes = {MediaType.APPLICATION_JSON_VALUE})
public class AuthenticationController {
    private final static Logger log = LoggerFactory.getLogger(
        AuthenticationController.class);
    private final TokenService tokenService;

    public AuthenticationController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("/login")
    public AuthenticationResponse authenticate(
            @AuthenticationPrincipal UserDetails userDetails) {
        log.debug("Generating token for user with name {}",
            userDetails.getUsername());
        String token = tokenService.generateAccessToken(userDetails);
        return new AuthenticationResponse(token);
    }
}
