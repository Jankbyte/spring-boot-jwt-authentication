package ru.jankbyte.spring.jwtauth.property;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(String secret, String issuer,
        ChronoUnit expiresUnit, long expiresAmmout) {
    public Duration getExpiresDuration() {
        return Duration.of(expiresAmmout, expiresUnit);
    }
}
