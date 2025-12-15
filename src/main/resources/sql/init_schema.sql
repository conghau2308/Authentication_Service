-- ================================
-- 🔄 RESET DATABASE OAUTH2 + USERS
-- ================================

-- Tắt kiểm tra khóa ngoại để tránh lỗi khi xóa bảng có quan hệ
SET FOREIGN_KEY_CHECKS = 0;

-- Xóa bảng theo thứ tự phụ thuộc (child → parent)
DROP TABLE IF EXISTS face_auth_logs;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS client_ownership;
DROP TABLE IF EXISTS developers;
DROP TABLE IF EXISTS oauth2_authorization_consent;
DROP TABLE IF EXISTS oauth2_authorization_codes;
DROP TABLE IF EXISTS oauth2_authorization;
DROP TABLE IF EXISTS oauth2_registered_client;
DROP TABLE IF EXISTS oauth2_refresh_tokens;

-- Bật lại kiểm tra khóa ngoại
SET FOREIGN_KEY_CHECKS = 1;

-- ================================
-- 🧱 TẠO LẠI CẤU TRÚC BẢNG
-- ================================

-- Bảng lưu trữ Client (ứng dụng đăng ký OAuth2)
CREATE TABLE IF NOT EXISTS oauth2_registered_client (
    id VARCHAR(100) NOT NULL,
    client_id VARCHAR(100) NOT NULL,
    client_id_issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret VARCHAR(200) DEFAULT NULL,
    client_secret_expires_at TIMESTAMP DEFAULT NULL,
    client_name VARCHAR(200) NOT NULL,
    client_authentication_methods VARCHAR(1000) NOT NULL,
    authorization_grant_types VARCHAR(1000) NOT NULL,
    redirect_uris VARCHAR(1000) DEFAULT NULL,
    post_logout_redirect_uris VARCHAR(1000) DEFAULT NULL,
    scopes VARCHAR(1000) NOT NULL,
    client_settings VARCHAR(2000) NOT NULL,
    token_settings VARCHAR(2000) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_client_id (client_id)
);

-- Bảng lưu trữ Authorization (mã code, token, refresh, id token)
CREATE TABLE IF NOT EXISTS oauth2_authorization (
    id VARCHAR(100) NOT NULL,
    registered_client_id VARCHAR(100) NOT NULL,
    principal_name VARCHAR(200) NOT NULL,
    authorization_grant_type VARCHAR(100) NOT NULL,
    authorized_scopes VARCHAR(1000) DEFAULT NULL,
    attributes TEXT DEFAULT NULL,
    state VARCHAR(500) DEFAULT NULL,
    authorization_code_value TEXT DEFAULT NULL,
    authorization_code_issued_at TIMESTAMP DEFAULT NULL,
    authorization_code_expires_at TIMESTAMP DEFAULT NULL,
    authorization_code_metadata TEXT DEFAULT NULL,
    access_token_value TEXT DEFAULT NULL,
    access_token_issued_at TIMESTAMP DEFAULT NULL,
    access_token_expires_at TIMESTAMP DEFAULT NULL,
    access_token_metadata TEXT DEFAULT NULL,
    access_token_type VARCHAR(100) DEFAULT NULL,
    access_token_scopes VARCHAR(1000) DEFAULT NULL,
    oidc_id_token_value TEXT DEFAULT NULL,
    oidc_id_token_issued_at TIMESTAMP DEFAULT NULL,
    oidc_id_token_expires_at TIMESTAMP DEFAULT NULL,
    oidc_id_token_metadata TEXT DEFAULT NULL,
    refresh_token_value TEXT DEFAULT NULL,
    refresh_token_issued_at TIMESTAMP DEFAULT NULL,
    refresh_token_expires_at TIMESTAMP DEFAULT NULL,
    refresh_token_metadata TEXT DEFAULT NULL,
    PRIMARY KEY (id)
);

-- Bảng lưu sự đồng ý (consent)
CREATE TABLE IF NOT EXISTS oauth2_authorization_consent (
    registered_client_id VARCHAR(100) NOT NULL,
    principal_name VARCHAR(200) NOT NULL,
    authorities VARCHAR(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);

-- Bảng developer (người tạo app OAuth2)
CREATE TABLE IF NOT EXISTS developers (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    company_name VARCHAR(255),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    account_non_expired BOOLEAN NOT NULL DEFAULT TRUE,
    account_non_locked BOOLEAN NOT NULL DEFAULT TRUE,
    credentials_non_expired BOOLEAN NOT NULL DEFAULT TRUE
);

-- Bảng liên kết Developer ↔ Client (ứng dụng)
CREATE TABLE IF NOT EXISTS client_ownership (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    developer_id BIGINT NOT NULL,
    client_id VARCHAR(100) NOT NULL,
    UNIQUE KEY uk_client_id_ownership (client_id),
    FOREIGN KEY (developer_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Bảng người dùng (end-users có thể dùng xác thực khuôn mặt)
CREATE TABLE users (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    -- Dữ liệu sinh trắc học WiFaKey (Helper Data & Key Hash)
    helper_data TEXT NOT NULL,
    key_hash TEXT NOT NULL,

    -- Thời gian ghi nhận
    enrolled_at DATETIME NOT NULL,
    last_verified_at DATETIME NULL
);

-- Bảng lưu Authorization Codes thủ công (nếu tách riêng)
CREATE TABLE oauth2_authorization_codes (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    code VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    redirect_uri VARCHAR(1000),
    scope VARCHAR(1000),
    state VARCHAR(255),
    nonce VARCHAR(255),
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(50),
    expires_at DATETIME(6) NOT NULL,
    used TINYINT(1) NOT NULL DEFAULT 0
);

CREATE TABLE oauth2_refresh_tokens (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    refresh_token VARCHAR(500) UNIQUE NOT NULL,
    username VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    scope VARCHAR(500),
    expires_at TIMESTAMP NOT NULL,
    issued_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP NULL,
    
    INDEX idx_refresh_token (refresh_token),
    INDEX idx_username_client (username, client_id),
    INDEX idx_expires_at (expires_at)
);

-- ================================
-- 🌱 DỮ LIỆU KHỞI TẠO
-- ================================

-- ================================
-- 🔍 KIỂM TRA DỮ LIỆU
-- ================================
SELECT * FROM developers;
SELECT * FROM client_ownership;
SELECT * FROM oauth2_registered_client;
SELECT * FROM oauth2_authorization_codes;
SELECT * FROM oauth2_refresh_tokens;
SELECT * FROM users;
SELECT * FROM user_face_data;