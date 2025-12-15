package com.Authentication.AuthService.services.auth;

import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.repository.UserRepository;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class DeveloperUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    // Tiêm (inject) Repository vào Service
    public DeveloperUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Hàm này được DemoLoginController gọi
     * @param username Đây chính là email mà developer gửi lên
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        
        // Dùng repository để tìm user bằng email
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> 
                        new UsernameNotFoundException("Không tìm thấy user: " + username)
                );
        
        return user; // Trả về đối tượng Developer (vì nó implement UserDetails)
    }
}