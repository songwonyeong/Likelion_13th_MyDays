package com.mydays.backend.auth.dto;

import jakarta.validation.constraints.*;

public class SignupDtos {
    public record RequestEmailCode(@Email @NotBlank String email) {}
    public record VerifyEmail(@Email @NotBlank String email,
                              @NotBlank @Pattern(regexp="^[0-9]{6}$") String code) {}
    public record FinalSignup(@Email @NotBlank String email,
                              @NotBlank @Size(min=8, max=72) String password,
                              @NotBlank String name,
                              @NotBlank String emailVerifiedToken) {}
    public record JwtResponse(String accessToken) {}
}
