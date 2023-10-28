package ru.jankbyte.spring.jwtauth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AuthenticationResponse(
    @JsonProperty("access_token") String accessToken) {
}
