package com.mydays.backend.application.auth;

import com.mydays.backend.domain.RefreshToken;
import com.mydays.backend.repository.RefreshTokenRepository;   // ✅ 기존 것 그대로 사용
import com.mydays.backend.util.HashUtil;                      // ✅ 기존 SHA-256 유틸 사용
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.servlet.http.HttpServletRequest;               // ✅ jakarta 네임스페이스
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository repo;
    private final SecureRandom random = new SecureRandom();

    @Value("${refresh.ttl-days:30}")
    private long ttlDays;

    @Value("${refresh.rotate-on-use:true}")
    private boolean rotateOnUse;

    /** refresh token 포맷: "{jti}.{secretBase64Url}" */
    private static String joinToken(String jti, String secretB64) { return jti + "." + secretB64; }

    private static String[] splitToken(String token) {
        int dot = token.indexOf('.');
        if (dot <= 0 || dot == token.length() - 1) throw new IllegalArgumentException("Malformed refresh token");
        return new String[]{ token.substring(0, dot), token.substring(dot + 1) };
    }

    /** 랜덤 secret 생성(Base64URL) */
    private String newSecretB64Url() {
        byte[] buf = new byte[48]; // 384bit
        random.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    /** 발급 */
    @Transactional
    public RefreshToken issue(Long memberId, String ua, String ip) {
        String jti = UUID.randomUUID().toString();
        String secretB64 = newSecretB64Url();
        String token = joinToken(jti, secretB64);

        // ✅ 네 util.HashUtil의 SHA-256 사용 (hex 64자) — 엔티티 tokenHash 길이(128)보다 짧아도 OK
        String tokenHash = HashUtil.sha256(secretB64);

        RefreshToken rt = RefreshToken.builder()
                .memberId(memberId)
                .jti(jti)
                .tokenHash(tokenHash)
                .userAgent(ua)
                .ip(ip)
                .expiresAt(Instant.now().plus(ttlDays, ChronoUnit.DAYS))
                .revoked(false)
                .rotated(false)
                .build();

        rt = repo.save(rt);
        rt.setToken(token); // plain 토큰은 일시 필드로만 반환
        return rt;
    }

    /** 검증 + (선택) 회전 */
    @Transactional
    public RefreshToken verifyAndMaybeRotate(String plainToken, String ua, String ip) {
        String[] parts = splitToken(plainToken);
        String jti = parts[0];
        String secretB64 = parts[1];

        RefreshToken stored = repo.findByJti(jti)
                .orElseThrow(() -> new IllegalArgumentException("Refresh token not found"));

        if (stored.getExpiresAt() == null || Instant.now().isAfter(stored.getExpiresAt())) {
            throw new IllegalStateException("Refresh token expired");
        }
        if (stored.isRevoked()) {
            throw new IllegalStateException("Refresh token revoked");
        }

        String presentedHash = HashUtil.sha256(secretB64);
        if (!presentedHash.equals(stored.getTokenHash())) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        if (!rotateOnUse) return stored; // 회전 비활성화 시 그대로 반환

        // 회전: 기존 토큰 폐기 + 새 토큰 발급
        stored.setRevoked(true);
        stored.setRotated(true);
        repo.save(stored);

        return issue(stored.getMemberId(), ua, ip);
    }

    /** 단일 토큰 폐기 */
    @Transactional
    public void revoke(String plainToken) {
        String[] parts = splitToken(plainToken);
        String jti = parts[0];
        repo.findByJti(jti).ifPresent(rt -> {
            rt.setRevoked(true);
            repo.save(rt);
        });
    }

    /** 회원의 모든 토큰 폐기 */
    @Transactional
    public void revokeAllFor(Long memberId) {
        repo.findAllByMemberId(memberId).forEach(rt -> {
            if (!rt.isRevoked()) {
                rt.setRevoked(true);
                repo.save(rt);
            }
        });
    }

    /** 프록시 환경 고려한 간단 IP 추출 (X-Forwarded-For 우선) */
    public static String safeIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        return req.getRemoteAddr();
    }
}
