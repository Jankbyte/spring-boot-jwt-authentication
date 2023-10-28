package ru.jankbyte.spring.jwtauth.config;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import ru.jankbyte.spring.jwtauth.property.JwtProperties;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration(proxyBeanMethods = false)
public class BearerSecurityConfig {
    private final SecretKey key;

    public BearerSecurityConfig(JwtProperties jwtProperties) {
        key = createKeyFromString(jwtProperties.secret());
    }

    private SecretKey createKeyFromString(String secret) {
        byte[] secretBytes = secret.getBytes();
        return new SecretKeySpec(secretBytes,"HmacSHA256");
    }

    @Bean
    public SecurityFilterChain bearerFilterChain(HttpSecurity http)
            throws Exception {
        return http.authorizeHttpRequests(request ->
                request.requestMatchers(SecurityConfig.PERMIT_ALL)
                        .permitAll()
                    .requestMatchers(SecurityConfig.ADMIN_ONLY_URLS)
                        .hasAuthority("SCOPE_ADMIN")
                    .anyRequest().authenticated())
            .oauth2ResourceServer(oauth2ResConf ->
                oauth2ResConf.jwt(Customizer.withDefaults()))
            .sessionManagement(session ->
                session.sessionCreationPolicy(STATELESS))
            .csrf(AbstractHttpConfigurer::disable)
            .build();
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        JWKSource<SecurityContext> source = new ImmutableSecret<>(key);
        return new NimbusJwtEncoder(source);
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withSecretKey(key)
            .build();
    }
}
