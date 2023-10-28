package ru.jankbyte.spring.jwtauth;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.*;

import static org.assertj.core.api.Assertions.assertThat;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAccessor;

public class JwtEncoderTest {
    private JwtEncoder jwtEncoder;
    private JwtDecoder jwtDecoder;

    @BeforeEach
    public void setup() {
        byte[] secretBytes = "my-super-secret-azazazazazazazaz".getBytes();
        SecretKey key = new SecretKeySpec(secretBytes,"HmacSHA256");
        jwtEncoder = new NimbusJwtEncoder(new ImmutableSecret<>(key));
        jwtDecoder = NimbusJwtDecoder.withSecretKey(key).build();
    }

    @Test
    public void shouldCreateJWT() {
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusSeconds(30);
        JwtClaimsSet claims = JwtClaimsSet.builder()
            .issuer("http://localhost:8080")
            .issuedAt(issuedAt).expiresAt(expiresAt)
            .notBefore(expiresAt).subject("max").build();
        JwsHeader jwsHeader = JwsHeader.with(() -> "HS256").build();
        JwtEncoderParameters params = JwtEncoderParameters.from(jwsHeader, claims);
        String token = jwtEncoder.encode(params).getTokenValue();
        Jwt jwt = jwtDecoder.decode(token);
        assertThat(expiresAt).isEqualTo(jwt.getExpiresAt());
    }
}
