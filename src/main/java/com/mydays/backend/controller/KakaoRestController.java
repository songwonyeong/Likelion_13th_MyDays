package com.mydays.backend.controller;

import com.mydays.backend.config.CurrentMember;
import com.mydays.backend.domain.Member;
import com.mydays.backend.dto.Tokens;
import com.mydays.backend.repository.MemberRepository;
import com.mydays.backend.service.KakaoService;
import com.mydays.backend.service.TokenService;
import io.swagger.v3.oas.annotations.Hidden;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.Map;

@RequiredArgsConstructor
@RestController
@RequestMapping("/kakao")
@Validated
public class KakaoRestController {

    private final KakaoService kakaoService;
    private final TokenService tokenService;
    private final MemberRepository memberRepository;

    // 프론트로 보낼 리다이렉트 목적지 (이미 개발된 흐름 유지)
    @Value("${frontend.redirect-uri:http://localhost:3000/main}")
    private String frontendRedirectUri;

    // Refresh 쿠키/정책을 프로퍼티로 일원화
    @Value("${refresh.cookie.name:refresh_token}") private String refreshCookieName;
    @Value("${refresh.cookie.secure:false}") private boolean refreshCookieSecure;
    @Value("${refresh.cookie.path:/}") private String refreshCookiePath;
    @Value("${refresh.cookie.same-site:Lax}") private String refreshCookieSameSite;
    @Value("${refresh.ttl-days:30}") private int refreshTtlDays;

    // --- Request DTOs --------------------------------------------------------

    @Data
    public static class RefreshRequest {
        // 바디로 전달 시 { "refreshToken": "rt_xxx" }
        @NotBlank(message = "refreshToken is required")
        private String refreshToken;
    }

    @Data
    public static class LogoutRequest {
        // 바디로 전달 시 { "refreshToken": "rt_xxx" } (쿠키/헤더가 있으면 생략 가능)
        private String refreshToken;
    }

    // --- Endpoints -----------------------------------------------------------

    /** GET /kakao/callback?code=... : 카카오 로그인 콜백 */
    @GetMapping("/callback")
    public ResponseEntity<?> callback(@RequestParam("code") String code,
                                      HttpServletRequest req,
                                      HttpServletResponse res) {
        try {
            String accessTokenFromKakao = kakaoService.getAccessToken(code);
            Map<String, Object> userInfo = kakaoService.getUserInfo(accessTokenFromKakao);

            // 회원 upsert + access/refresh 발급 (TokenService 내부 회전 규칙 일관 적용)
            Tokens tokens = kakaoService.processUser(userInfo);

            // refresh를 HttpOnly 쿠키로 내려줌 (access는 URL/바디로 노출하지 않음)
            setRefreshCookie(res, tokens.getRefresh());

            // ✅ JSON 대신 프론트로 302 리다이렉트 (리다이렉트 URI는 프로퍼티 유지)
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(frontendRedirectUri))
                    .build();

        } catch (Exception e) {
            // 실패 시 프론트로 돌려보내고, 필요하면 쿼리로 에러 표시
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(frontendRedirectUri + "?error=oauth"))
                    .build();
        }
    }

    /** POST /kakao/auth/refresh : refresh로 새 access 발급(회전) */
    @PostMapping("/auth/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest req,
                                     HttpServletResponse res,
                                     @RequestHeader(value = "X-Refresh", required = false) String hdrRefresh,
                                     @RequestBody(required = false) RefreshRequest body // 쿠키/헤더 쓰면 바디 생략 가능
    ) {
        String cookieRefresh = readRefreshCookie(req);
        String bodyRefresh = (body != null) ? body.getRefreshToken() : null;
        String provided = firstNonEmpty(cookieRefresh, hdrRefresh, bodyRefresh);

        if (!StringUtils.hasText(provided)) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status","error","message","Refresh token missing"
            ));
        }

        var tokens = tokenService.refresh(provided,
                req.getHeader("User-Agent"), clientIp(req));

        // 회전된 새 refresh를 쿠키로 내려줌
        setRefreshCookie(res, tokens.refresh());

        return ResponseEntity.ok(Map.of(
                "status","success",
                "access", tokens.access()
        ));
    }

    /** POST /kakao/auth/logout : 현재 디바이스 로그아웃(해당 refresh만 폐기) */
    @PostMapping("/auth/logout")
    public ResponseEntity<?> logout(HttpServletRequest req,
                                    HttpServletResponse res,
                                    @RequestHeader(value = "X-Refresh", required = false) String hdrRefresh,
                                    @RequestBody(required = false) LogoutRequest body
    ) {
        String cookieRefresh = readRefreshCookie(req);
        String bodyRefresh = (body != null) ? body.getRefreshToken() : null;
        String provided = firstNonEmpty(cookieRefresh, hdrRefresh, bodyRefresh);

        if (!StringUtils.hasText(provided)) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status","error","message","Refresh token missing"
            ));
        }

        tokenService.revokeOneByRefresh(provided);
        clearRefreshCookie(res);

        return ResponseEntity.ok(Map.of(
                "status","success","message","Logged out on this device"
        ));
    }

    /** POST /kakao/auth/logout-all : 모든 기기에서 로그아웃(멤버 전체 refresh 폐기) */
    @Hidden
    @PostMapping("/auth/logout-all")
    public ResponseEntity<?> logoutAll(@CurrentMember Member member,
                                       HttpServletResponse res) {
        if (member == null) {
            return ResponseEntity.status(401).body(Map.of(
                    "status","error","message","Unauthorized"
            ));
        }
        long n = tokenService.revokeAllFor(member.getId());
        clearRefreshCookie(res);
        return ResponseEntity.ok(Map.of(
                "status","success",
                "revoked", n
        ));
    }

    /** GET /kakao/logout-url : 카카오 로그아웃 리디렉트 URL */
    @Hidden
    @GetMapping("/logout-url")
    public ResponseEntity<?> logoutUrl() {
        return ResponseEntity.ok(Map.of(
                "logoutUrl", kakaoService.buildKakaoLogoutUrl()
        ));
    }

    // --- Helpers -------------------------------------------------------------

    private String readRefreshCookie(HttpServletRequest req) {
        if (req.getCookies() == null) return null;
        for (Cookie c : req.getCookies()) {
            if (refreshCookieName.equals(c.getName())) return c.getValue();
        }
        return null;
    }

    private void setRefreshCookie(HttpServletResponse res, String refresh) {
        int maxAgeSec = refreshTtlDays * 24 * 60 * 60;

        Cookie c = new Cookie(refreshCookieName, refresh);
        c.setHttpOnly(true);
        c.setSecure(refreshCookieSecure);   // 배포(HTTPS) 시 true 권장
        c.setPath(refreshCookiePath);
        c.setMaxAge(maxAgeSec);
        res.addCookie(c);

        // SameSite 보완 헤더 (표준 Cookie API 미지원)
        res.addHeader("Set-Cookie",
                String.format("%s=%s; Max-Age=%d; Path=%s; %s; HttpOnly; SameSite=%s",
                        refreshCookieName, refresh, maxAgeSec, refreshCookiePath,
                        refreshCookieSecure ? "Secure" : "", refreshCookieSameSite));
    }

    private void clearRefreshCookie(HttpServletResponse res) {
        Cookie c = new Cookie(refreshCookieName, "");
        c.setHttpOnly(true);
        c.setSecure(refreshCookieSecure);
        c.setPath(refreshCookiePath);
        c.setMaxAge(0);
        res.addCookie(c);

        res.addHeader("Set-Cookie",
                String.format("%s=; Max-Age=0; Path=%s; %s; HttpOnly; SameSite=%s",
                        refreshCookieName, refreshCookiePath,
                        refreshCookieSecure ? "Secure" : "", refreshCookieSameSite));
    }

    private static String clientIp(HttpServletRequest req) {
        String fwd = req.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(fwd)) return fwd.split(",")[0].trim();
        return req.getRemoteAddr();
    }

    private static String firstNonEmpty(String... vals) {
        for (String v : vals) if (StringUtils.hasText(v)) return v;
        return null;
    }
}
