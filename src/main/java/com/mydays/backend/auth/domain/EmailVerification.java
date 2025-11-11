package com.mydays.backend.auth.domain;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "email_verification")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EmailVerification {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable=false, length=190)
    private String email;

    @Column(nullable=false, length=255)
    private String codeHash;

    @Column(nullable=false)
    private LocalDateTime expiresAt;

    @Builder.Default
    @Column(nullable=false)
    private boolean used = false;

    @Builder.Default
    @Column(nullable=false)
    private int attempts = 0;

    public void increaseAttempts() { this.attempts++; }
    public boolean isExpired() { return LocalDateTime.now().isAfter(expiresAt); }
}
