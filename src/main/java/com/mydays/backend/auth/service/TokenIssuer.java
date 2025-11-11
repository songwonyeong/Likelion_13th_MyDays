package com.mydays.backend.auth.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class TokenIssuer {

    private final SecretKey key;
    private final long accessTokenMillis;

    public TokenIssuer(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-ttl-minutes:120}") long ttlMinutes
    ) {
        // ✅ JwtAuthFilter와 동일한 방식으로 키 생성 (Keys.hmacShaKeyFor + UTF-8)
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenMillis = ttlMinutes * 60L * 1000L;
    }

    /** JwtAuthFilter가 기대하는 클레임(memberId)을 포함해 발급 */
    public String issueAccessToken(Long memberId, String email, String role) {
        Date now = new Date();
        Date exp = new Date(now.getTime() + accessTokenMillis);

        return Jwts.builder()
                // subject는 필수 아님(필터는 subject 안 씀) — 참고용으로 memberId 세팅
                .setSubject(String.valueOf(memberId))
                // ✅ 필수: 필터가 읽는 클레임
                .claim("memberId", memberId)
                // 부가 정보(선택)
                .claim("email", email)
                .claim("role", role == null ? "USER" : role)
                .setIssuedAt(now)
                .setExpiration(exp)
                // jjwt 0.11.x 스타일: Key 또는 byte[] 사용 가능
                .signWith(SignatureAlgorithm.HS256, key)
                .compact();
    }
}

