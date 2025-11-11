package com.mydays.backend.auth.controller;

import com.mydays.backend.application.auth.RefreshTokenService;
import com.mydays.backend.auth.service.TokenIssuer;
import com.mydays.backend.auth.dto.SignupDtos.JwtResponse;
import com.mydays.backend.domain.Member;
import com.mydays.backend.repository.MemberRepository; // 네 기존 위치
import com.mydays.backend.util.CookieUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth/token")
public class TokenController {

    private final RefreshTokenService refreshTokenService;
    private final TokenIssuer tokenIssuer;
    private final MemberRepository memberRepository;

    @Value("${refresh.cookie.name:refresh_token}") private String refreshCookieName;
    @Value("${refresh.cookie.secure:false}") private boolean refreshCookieSecure;
    @Value("${refresh.cookie.path:/}") private String refreshCookiePath;
    @Value("${refresh.cookie.same-site:Lax}") private String refreshCookieSameSite;
    @Value("${refresh.ttl-days:30}") private int refreshTtlDays;

    public TokenController(RefreshTokenService refreshTokenService,
                           TokenIssuer tokenIssuer,
                           MemberRepository memberRepository) {
        this.refreshTokenService = refreshTokenService;
        this.tokenIssuer = tokenIssuer;
        this.memberRepository = memberRepository;
    }

    private String readRefreshFromCookie(HttpServletRequest req) {
        Cookie[] cookies = req.getCookies();
        if (cookies == null) return null;
        for (Cookie c : cookies) {
            if (refreshCookieName.equals(c.getName())) return c.getValue();
        }
        return null;
    }

    /** 토큰 갱신(회전 포함) */
    @PostMapping("/refresh")
    public ResponseEntity<JwtResponse> refresh(HttpServletRequest req, HttpServletResponse res,
                                               @RequestParam(value="token", required=false) String tokenInBodyOrQuery) {
        String presented = tokenInBodyOrQuery;
        if (presented == null || presented.isBlank()) {
            presented = readRefreshFromCookie(req);
        }
        if (presented == null || presented.isBlank()) {
            return ResponseEntity.badRequest().build();
        }

        var newRt = refreshTokenService.verifyAndMaybeRotate(
                presented, req.getHeader("User-Agent"), RefreshTokenService.safeIp(req));

        // 액세스 재발급
        Member m = memberRepository.findById(newRt.getMemberId())
                .orElseThrow(() -> new IllegalStateException("user not found"));

        String newAccess = tokenIssuer.issueAccessToken(m.getId(), m.getEmail(), "USER");

        // 리프레시도 새로 쿠키에 (회전 시)
        int maxAgeSec = refreshTtlDays * 24 * 60 * 60;
        if (newRt.getToken() != null) { // rotate된 경우 plain token이 일시 필드에 담겨있음
            CookieUtil.add(res, refreshCookieName, newRt.getToken(), maxAgeSec,
                    refreshCookiePath, refreshCookieSecure, refreshCookieSameSite);
        }

        return ResponseEntity.ok(new JwtResponse(newAccess));
    }

    /** 로그아웃(현재 리프레시 폐기) */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest req, HttpServletResponse res,
                                       @RequestParam(value="token", required=false) String tokenInBodyOrQuery) {
        String presented = tokenInBodyOrQuery;
        if (presented == null || presented.isBlank()) {
            presented = readRefreshFromCookie(req);
        }
        if (presented != null && !presented.isBlank()) {
            refreshTokenService.revoke(presented);
        }
        // 쿠키도 비우기
        CookieUtil.delete(res, refreshCookieName, refreshCookiePath, refreshCookieSecure, refreshCookieSameSite);
        return ResponseEntity.ok().build();
    }
}
