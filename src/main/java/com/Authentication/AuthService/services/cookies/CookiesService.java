package com.Authentication.AuthService.services.cookies;

import org.springframework.stereotype.Service;

import com.Authentication.AuthService.config.CookieConfig;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CookiesService {
    private final CookieConfig cookieConfig;

    private void setSecureCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(true); // Chỉ gửi qua HTTPS (production)
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        cookie.setAttribute("SameSite", "None");
        // CSRF protection + bật strict nếu đã có frontend + backend cùng domain
        response.addCookie(cookie);
    }

    private void clearCookie(HttpServletResponse response, String name) {
        Cookie cookie = new Cookie(name, null);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    public void clearAccessTokenCookie(HttpServletResponse response) {
        clearCookie(response, cookieConfig.getAccessTokenName());
    }

    public void clearAllCookies(HttpServletResponse response) {
        clearCookie(response, cookieConfig.getAccessTokenName());
        clearCookie(response, cookieConfig.getRefreshTokenName());
    }

    public void setSecureAllCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        setSecureCookie(response, cookieConfig.getAccessTokenName(), accessToken, cookieConfig.getAccessTokenMaxAge());
        setSecureCookie(response, cookieConfig.getRefreshTokenName(), refreshToken,
                cookieConfig.getRefreshTokenMaxAge());
    }

    public void setSecureAccessCookie(HttpServletResponse response, String accessToken) {
        setSecureCookie(response, cookieConfig.getAccessTokenName(), accessToken, cookieConfig.getAccessTokenMaxAge());
    }
}
