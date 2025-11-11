package com.mydays.backend.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

public class CookieUtil {
    public static void add(HttpServletResponse res, String name, String value, int maxAgeSec,
                           String path, boolean secure, String sameSite) {
        Cookie c = new Cookie(name, value);
        c.setHttpOnly(true);
        c.setSecure(secure);
        c.setPath(path == null ? "/" : path);
        c.setMaxAge(maxAgeSec);
        res.addCookie(c);

        // SameSite 보완 헤더
        String header = String.format("%s=%s; Max-Age=%d; Path=%s; %s; HttpOnly; SameSite=%s",
                name, value, maxAgeSec, c.getPath(), secure ? "Secure" : "", sameSite == null ? "Lax" : sameSite);
        res.addHeader("Set-Cookie", header);
    }

    public static void delete(HttpServletResponse res, String name, String path, boolean secure, String sameSite) {
        add(res, name, "", 0, path, secure, sameSite);
    }
}
