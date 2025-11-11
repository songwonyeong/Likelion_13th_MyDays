package com.mydays.backend.auth.controller;

import com.mydays.backend.auth.dto.SignupDtos.*;
import com.mydays.backend.auth.service.EmailVerificationService;
import com.mydays.backend.auth.service.TokenIssuer;
import com.mydays.backend.application.auth.RefreshTokenService;
import com.mydays.backend.application.member.MemberSignupService;
import com.mydays.backend.util.CookieUtil;
import com.mydays.backend.domain.Member;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth/signup")
public class SignupController {

    private final EmailVerificationService emailVerificationService;
    private final MemberSignupService memberSignupService;
    private final TokenIssuer tokenIssuer;
    private final RefreshTokenService refreshTokenService;

    @Value("${refresh.cookie.name:refresh_token}") private String refreshCookieName;
    @Value("${refresh.cookie.secure:false}") private boolean refreshCookieSecure;
    @Value("${refresh.cookie.path:/}") private String refreshCookiePath;
    @Value("${refresh.cookie.same-site:Lax}") private String refreshCookieSameSite;
    @Value("${refresh.ttl-days:30}") private int refreshTtlDays;

    public SignupController(EmailVerificationService emailVerificationService,
                            MemberSignupService memberSignupService,
                            TokenIssuer tokenIssuer,
                            RefreshTokenService refreshTokenService) {
        this.emailVerificationService = emailVerificationService;
        this.memberSignupService = memberSignupService;
        this.tokenIssuer = tokenIssuer;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/request-email-code")
    public ResponseEntity<Void> requestEmailCode(@Valid @RequestBody RequestEmailCode req) {
        emailVerificationService.requestCode(req.email());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(@Valid @RequestBody VerifyEmail req) {
        String emailJwt = emailVerificationService.verifyCodeAndIssueEmailJwt(req.email(), req.code());
        return ResponseEntity.ok(emailJwt);
    }

    @PostMapping
    public ResponseEntity<JwtResponse> signup(@Valid @RequestBody FinalSignup req,
                                              HttpServletRequest httpReq,
                                              HttpServletResponse httpRes) {
        // 1) 이메일 인증 토큰 검증 + 로컬 회원 생성
        Member m = memberSignupService.signupLocal(
                req.email(), req.password(), req.name(), req.emailVerifiedToken());

        // 2) Access 토큰 발급 (JwtAuthFilter와 호환: memberId 클레임 포함)
        String accessToken = tokenIssuer.issueAccessToken(m.getId(), m.getEmail(), "USER");

        // 3) Refresh 토큰 발급 → HttpOnly 쿠키로 내려주기
        String ua = httpReq.getHeader("User-Agent");
        String ip = RefreshTokenService.safeIp(httpReq);
        var rt = refreshTokenService.issue(m.getId(), ua, ip);

        int maxAgeSec = refreshTtlDays * 24 * 60 * 60;
        CookieUtil.add(httpRes, refreshCookieName, rt.getToken(), maxAgeSec,
                refreshCookiePath, refreshCookieSecure, refreshCookieSameSite);

        // 4) 응답: Access 토큰만 바디로 전달
        return ResponseEntity.ok(new JwtResponse(accessToken));
    }
}
