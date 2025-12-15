package com.Authentication.AuthService.controller;

import com.Authentication.AuthService.dto.LoginDto;
import com.Authentication.AuthService.services.auth.DeveloperUserDetailsService; // <-- Service của bạn
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/portal")
public class DemoLoginController {

    private final DeveloperUserDetailsService developerUserDetailsService;

    public DemoLoginController(DeveloperUserDetailsService developerUserDetailsService) {
        this.developerUserDetailsService = developerUserDetailsService;
    }

    @PostMapping("/demo-login")
    public ResponseEntity<?> demoLogin(@RequestBody LoginDto loginDto, HttpServletRequest request) {
        try {
            // 1. Tìm developer bằng username (email)
            UserDetails developer = developerUserDetailsService.loadUserByUsername(loginDto.getUsername());

            // 2. Tạo một đối tượng Authentication (đã xác thực)
            // Chúng ta truyền `null` vào password
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    developer,
                    null, // Không có password
                    developer.getAuthorities()
            );

            // 3. Thiết lập bối cảnh bảo mật (Security Context)
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);

            // 4. Lưu context vào HTTP Session
            // Đây là bước tạo cookie "JSESSIONID"
            HttpSession session = request.getSession(true);
            session.setAttribute("SPRING_SECURITY_CONTEXT", context);

            return ResponseEntity.ok().body("Đăng nhập demo thành công");

        } catch (Exception e) {
            return ResponseEntity.status(401).body("Không tìm thấy user");
        }
    }
}