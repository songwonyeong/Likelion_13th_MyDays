package com.mydays.backend.auth.domain;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "email_verification")
public class EmailVerification {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable=false, length=190)
    private String email;

    @Column(nullable=false, length=255)
    private String codeHash;       // 6자리 코드 해시(원문 저장X)

    @Column(nullable=false)
    private LocalDateTime expiresAt;

    @Column(nullable=false)
    private boolean used = false;

    @Column(nullable=false)
    private int attempts = 0;

    public void increaseAttempts() { this.attempts++; }
    public boolean isExpired() { return LocalDateTime.now().isAfter(expiresAt); }

    // getters/setters ...
}
