package com.mydays.backend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityCryptoConfig {
    @Bean
    public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }

    public static String bcrypt(String raw)     { return BCrypt.hashpw(raw, BCrypt.gensalt(10)); }
    public static boolean bcryptMatches(String raw, String hash) { return BCrypt.checkpw(raw, hash); }
}
