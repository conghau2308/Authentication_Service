package com.Authentication.AuthService.services.auth;

import com.Authentication.AuthService.entity.Developer; // <-- Import entity của bạn
import com.Authentication.AuthService.repository.DeveloperRepository; // <-- Import repo của bạn
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class DeveloperUserDetailsService implements UserDetailsService {

    private final DeveloperRepository developerRepository;

    // Tiêm (inject) Repository vào Service
    public DeveloperUserDetailsService(DeveloperRepository developerRepository) {
        this.developerRepository = developerRepository;
    }

    /**
     * Hàm này được DemoLoginController gọi
     * @param username Đây chính là email mà developer gửi lên
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        
        // Dùng repository để tìm user bằng email
        Developer developer = developerRepository.findByEmail(username)
                .orElseThrow(() -> 
                        new UsernameNotFoundException("Không tìm thấy user: " + username)
                );
        
        return developer; // Trả về đối tượng Developer (vì nó implement UserDetails)
    }
}