package ru.jankbyte.spring.jwtauth.controller;

import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.Collection;

@RestController
@RequestMapping(path = "/api/securityTest", consumes = {
    MediaType.APPLICATION_JSON_VALUE
})
public class AuthenticationTestController {
    @GetMapping("/info")
    public String showAuthenticated(@AuthenticationPrincipal Jwt jwt) {
        String username = jwt.getSubject();
        Collection<String> scopes = jwt.getClaim("scope");
        return """
            Username: %s
            Roles: %s
            """.formatted(username, scopes);
    }

    @GetMapping("/admin")
    public String showAdminContent() {
        return "This content can see only user with ADMIN role";
    }
}
