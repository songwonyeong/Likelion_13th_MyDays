package com.mydays.backend.auth.repository;

import com.mydays.backend.auth.domain.EmailVerification;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface EmailVerificationRepository extends JpaRepository<EmailVerification, Long> {
    Optional<EmailVerification> findTopByEmailAndUsedIsFalseOrderByIdDesc(String email);
}
