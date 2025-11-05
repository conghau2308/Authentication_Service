package com.Authentication.AuthService.entity;

import jakarta.persistence.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails; // <-- IMPORT CÁI NÀY

import java.util.Collection;
import java.util.List;

@Entity
@Table(name = "developers")
// SỬA DÒNG NÀY: Thêm "implements UserDetails"
public class Developer implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email; // Sẽ dùng email làm username

    // Bạn có thể không có cột password, nhưng vẫn cần override hàm
    // private String password; 

    // ... (các trường khác của bạn)

    // --- CÁC HÀM BẮT BUỘC CỦA USERDETAILS ---
    
    @Override
    public String getUsername() {
        // Trả về email (mà bạn dùng làm username)
        return this.email; 
    }

    @Override
    public String getPassword() {
        // Vì bạn demo không cần password, chỉ cần trả về null
        return null;
    }
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Luôn gán cho họ quyền "ROLE_DEVELOPER"
        return List.of(new SimpleGrantedAuthority("ROLE_DEVELOPER"));
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // Mặc định là true
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // Mặc định là true
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // Mặc định là true
    }

    @Override
    public boolean isEnabled() {
        return true; // Mặc định là true
    }

    // --- Getters / Setters cho các trường của bạn ---
    
    public Long getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}