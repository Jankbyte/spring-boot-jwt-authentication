package ru.jankbyte.spring.jwtauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.springframework.core.Ordered.HIGHEST_PRECEDENCE;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


import java.util.Collection;
import java.util.List;

@Configuration(proxyBeanMethods = false)
public class SecurityConfig {
    public static final String[] ADMIN_ONLY_URLS = {
        "/api/securityTest/admin*"
    };

    public static final String[] PERMIT_ALL = { "/error" };

    @Bean
    @Order(HIGHEST_PRECEDENCE)
    public SecurityFilterChain basicFilterChain(HttpSecurity http) throws Exception {
        String jwtAccessTokenUrl = "/api/authentication/login*";
        return http.authorizeHttpRequests(request ->
                request.requestMatchers(PERMIT_ALL).permitAll()
                    .requestMatchers(jwtAccessTokenUrl).authenticated()
                    .anyRequest().denyAll())
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session ->
                session.sessionCreationPolicy(STATELESS))
            .securityMatcher(jwtAccessTokenUrl)
            .httpBasic(Customizer.withDefaults())
            .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        Collection<UserDetails> users = List.of(
            buildUser("max", "max123", "USER"),
            buildUser("alex", "alex123", "ADMIN")
        );
        return new InMemoryUserDetailsManager(users);
    }

    private User buildUser(String name, String password, String... authorities) {
        return (User) User.withUsername(name).password(password)
            .passwordEncoder(origPassword -> passwordEncoder().encode(origPassword))
            .authorities(authorities)
            .build();
    }
}
