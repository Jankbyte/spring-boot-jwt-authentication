package ru.jankbyte.spring.jwtauth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import ru.jankbyte.spring.jwtauth.property.JwtProperties;

import java.time.Instant;
import java.util.Collection;

@Service
public class TokenService {
    private static final Logger log = LoggerFactory.getLogger(
        TokenService.class);

    private final JwtEncoder encoder;
    private final JwtProperties jwtProperties;

    public TokenService(JwtEncoder encoder, JwtProperties jwtProperties) {
        this.encoder = encoder;
        this.jwtProperties = jwtProperties;
    }

    public String generateAccessToken(UserDetails userDetails) {
        JwtClaimsSet claims = convertDetailsToJwt(userDetails);
        JwsHeader jwsHeader = JwsHeader.with(() -> "HS256").build();
        JwtEncoderParameters params = JwtEncoderParameters.from(
            jwsHeader, claims);
        log.debug("Generating JWT token for user: {}", userDetails);
        return encoder.encode(params).getTokenValue();
    }

    private JwtClaimsSet convertDetailsToJwt(UserDetails userDetails) {
        Collection<String> roles = userDetails.getAuthorities()
            .stream().map(GrantedAuthority::getAuthority).toList();
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(30,
            jwtProperties.expiresUnit());
        return JwtClaimsSet.builder()
            .issuer(jwtProperties.issuer())
            .issuedAt(issuedAt).expiresAt(expiresAt)
            .subject(userDetails.getUsername())
            .claim("scope", roles).build();
    }
}
