package com.mydays.backend.auth.service;

import com.mydays.backend.auth.domain.EmailVerification;
import com.mydays.backend.auth.repository.EmailVerificationRepository;
import com.mydays.backend.config.SecurityCryptoConfig;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;
import java.util.Date;

@Service
public class EmailVerificationService {

    private final EmailVerificationRepository repo;
    private final MailSenderService mail;
    private final byte[] emailJwtSecret;
    private final int codeTtlMinutes;
    private final int emailJwtTtlMinutes;
    private final int maxAttempts;
    private final Random random = new Random();

    public EmailVerificationService(
            EmailVerificationRepository repo,
            MailSenderService mail,
            @Value("${signup.email.jwt.secret}") String jwtSecret,
            @Value("${signup.email.code.ttl-minutes:10}") int codeTtlMinutes,
            @Value("${signup.email.jwt.ttl-minutes:15}") int emailJwtTtlMinutes,
            @Value("${signup.email.code.max-attempts:5}") int maxAttempts
    ) {
        this.repo = repo;
        this.mail = mail;
        this.emailJwtSecret = jwtSecret.getBytes();
        this.codeTtlMinutes = codeTtlMinutes;
        this.emailJwtTtlMinutes = emailJwtTtlMinutes;
        this.maxAttempts = maxAttempts;
    }

    @Transactional
    public void requestCode(String email) {
        String code = generate6Digit();
        String hash = SecurityCryptoConfig.bcrypt(code);

        // 🔁 세터 대신 빌더로 새 레코드 생성
        EmailVerification ev = EmailVerification.builder()
                .email(email)
                .codeHash(hash)
                .expiresAt(LocalDateTime.now().plusMinutes(codeTtlMinutes))
                .used(false)        // 엔티티에 필드가 있다면 명시
                .attempts(0)        // 엔티티에 필드가 있다면 명시
                .build();

        repo.save(ev);

        // 메일 발송
        mail.sendVerificationCode(email, code);
    }

    @Transactional
    public String verifyCodeAndIssueEmailJwt(String email, String code) {
        Optional<EmailVerification> opt = repo.findTopByEmailAndUsedIsFalseOrderByIdDesc(email);
        EmailVerification ev = opt.orElseThrow(() -> new IllegalArgumentException("먼저 인증코드를 요청해주세요."));

        if (ev.isExpired()) throw new IllegalStateException("인증코드가 만료됐습니다. 다시 요청해주세요.");
        if (ev.getAttempts() >= maxAttempts) throw new IllegalStateException("인증 시도 횟수를 초과했습니다. 다시 요청해주세요.");

        ev.increaseAttempts();

        boolean matched = SecurityCryptoConfig.bcryptMatches(code, ev.getCodeHash());
        if (!matched) {
            repo.save(ev);
            throw new IllegalArgumentException("인증코드가 올바르지 않습니다.");
        }

        ev.setUsed(true);
        repo.save(ev);

        Date now = new Date();
        Date exp = new Date(now.getTime() + emailJwtTtlMinutes * 60L * 1000L);

        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(SignatureAlgorithm.HS256, emailJwtSecret)
                .compact();
    }

    public String parseEmailFromEmailJwt(String jwt) {
        return Jwts.parser()
                .setSigningKey(emailJwtSecret)
                .parseClaimsJws(jwt)
                .getBody()
                .getSubject();
    }

    private String generate6Digit() {
        return String.format("%06d", random.nextInt(1_000_000));
    }
}
