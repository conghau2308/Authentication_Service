package com.Authentication.AuthService.services.user;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.Authentication.AuthService.entity.User;
import com.Authentication.AuthService.repository.UserRepository;

@Service
public class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Tìm user theo username
     */
    public User findByUsername(String username) {
        Optional<User> user = userRepository.findByUsername(username);
        return user.orElse(null);
    }

    /**
     * Tìm user theo ID
     */
    public User findById(Long id) {
        Optional<User> user = userRepository.findById(id);
        return user.orElse(null);
    }

    /**
     * Lưu hoặc cập nhật user
     */
    public User save(User user) {
        return userRepository.save(user);
    }

    /**
     * Kiểm tra user có tồn tại không
     */
    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }
}
