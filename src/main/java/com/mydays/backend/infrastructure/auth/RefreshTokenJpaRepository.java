package com.mydays.backend.infrastructure.auth;

import com.mydays.backend.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenJpaRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByJtiAndRevokedFalse(String jti);
    long countByMemberIdAndRevokedFalseAndExpiresAtAfter(Long memberId, Instant now);
}
