-- =====================================================
-- DROP TABLES IF EXISTS (theo thứ tự ngược FK)
-- =====================================================
DROP TABLE IF EXISTS oauth2_client_secrets CASCADE;

DROP TABLE IF EXISTS oauth2_client_members CASCADE;

DROP TABLE IF EXISTS oauth2_clients CASCADE;

DROP TABLE IF EXISTS users CASCADE;

DROP TABLE IF EXISTS oauth2_user_consents CASCADE;

-- Drop schema nếu cần tạo lại hoàn toàn
-- DROP SCHEMA IF EXISTS auth_service CASCADE;
-- =====================================================
-- CREATE SCHEMA
-- =====================================================
CREATE SCHEMA IF NOT EXISTS auth_service;

-- Set search path
SET
    search_path TO auth_service,
    public;

-- =====================================================
-- TABLE: users
-- =====================================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    helper_data TEXT NOT NULL,
    mask TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'USER',
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_verified_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes cho users
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);

CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- Comments cho users
COMMENT ON TABLE users IS 'Bảng lưu trữ thông tin user';

COMMENT ON COLUMN users.helper_data IS 'Dữ liệu hỗ trợ xác thực';

COMMENT ON COLUMN users.key_hash IS 'Dữ liệu hỗ trợ xác thực';

COMMENT ON COLUMN users.last_verified_at IS 'Lần xác thực gần nhất';

-- =====================================================
-- TABLE: oauth2_clients
-- =====================================================
CREATE TABLE IF NOT EXISTS oauth2_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) NOT NULL UNIQUE,
    client_name VARCHAR(255) NOT NULL,
    client_type VARCHAR(50) NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes TEXT,
    grant_types TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    -- Foreign Key
    CONSTRAINT fk_oauth2_clients_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE
    SET
        NULL
);

-- Indexes cho oauth2_clients
CREATE INDEX IF NOT EXISTS idx_oauth2_clients_client_id ON oauth2_clients(client_id);

CREATE INDEX IF NOT EXISTS idx_oauth2_clients_is_active ON oauth2_clients(is_active);

CREATE INDEX IF NOT EXISTS idx_oauth2_clients_client_type ON oauth2_clients(client_type);

CREATE INDEX IF NOT EXISTS idx_oauth2_clients_created_by ON oauth2_clients(created_by);

-- Comments cho oauth2_clients
COMMENT ON TABLE oauth2_clients IS 'Lưu trữ thông tin các OAuth2 clients';

COMMENT ON COLUMN oauth2_clients.client_id IS 'Mã định danh duy nhất của client';

COMMENT ON COLUMN oauth2_clients.grant_types IS 'Các loại grant types được phân cách bởi dấu +';

COMMENT ON COLUMN oauth2_clients.scopes IS 'Các scopes được phân cách bởi dấu +';

-- =====================================================
-- TABLE: oauth2_client_members
-- =====================================================
CREATE TABLE IF NOT EXISTS oauth2_client_members (
    id BIGSERIAL PRIMARY KEY,
    client_id UUID NOT NULL,
    user_id UUID NOT NULL,
    role VARCHAR(50) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    added_by UUID,
    -- Foreign Keys
    CONSTRAINT fk_member_client FOREIGN KEY (client_id) REFERENCES oauth2_clients(id) ON DELETE CASCADE,
    CONSTRAINT fk_member_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_member_added_by FOREIGN KEY (added_by) REFERENCES users(id) ON DELETE
    SET
        NULL,
        -- Unique Constraint: 1 user không được thêm 2 lần vào cùng 1 client
        CONSTRAINT uk_client_user UNIQUE (client_id, user_id)
);

-- Indexes cho oauth2_client_members (tên unique)
CREATE INDEX IF NOT EXISTS idx_members_client_id ON oauth2_client_members(client_id);

CREATE INDEX IF NOT EXISTS idx_members_user_id ON oauth2_client_members(user_id);

CREATE INDEX IF NOT EXISTS idx_members_is_active ON oauth2_client_members(is_active);

CREATE INDEX IF NOT EXISTS idx_members_added_by ON oauth2_client_members(added_by);

-- Composite index cho query phổ biến
CREATE INDEX IF NOT EXISTS idx_members_client_user_active ON oauth2_client_members(client_id, user_id, is_active);

-- Comments
COMMENT ON TABLE oauth2_client_members IS 'Bảng quản lý members của OAuth2 clients';

COMMENT ON COLUMN oauth2_client_members.role IS 'Vai trò của member trong client (OWNER, ADMIN, DEVELOPER, VIEWER)';

COMMENT ON COLUMN oauth2_client_members.is_active IS 'Trạng thái active của member';

COMMENT ON COLUMN oauth2_client_members.added_by IS 'User ID của người thêm member này';

-- =====================================================
-- TABLE: oauth2_client_secrets
-- =====================================================
CREATE TABLE IF NOT EXISTS oauth2_client_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL,
    secret_hash TEXT NOT NULL,
    secret_hint VARCHAR(100) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_by UUID,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP,
    revoked_by UUID,
    -- Foreign Keys
    CONSTRAINT fk_secret_client FOREIGN KEY (client_id) REFERENCES oauth2_clients(id) ON DELETE CASCADE,
    CONSTRAINT fk_secret_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE
    SET
        NULL,
        CONSTRAINT fk_secret_revoked_by FOREIGN KEY (revoked_by) REFERENCES users(id) ON DELETE
    SET
        NULL,
        -- Check constraint
        CONSTRAINT chk_revoked_logic CHECK (
            -- Cho phép Thêm lúc ban đầu khi chưa từng bị revoke cả đều 2 null
            -- Hoặc đã từng bị revoke (revoked_at not null) nhưng user revoked đã bị xóa (revoked_by is null)
            -- Hoặc trường hợp revoke nhưng user chua xóa cả 2 đều not null
            NOT (
                revoked_at IS NULL
                AND revoked_by IS NOT NULL
            )
        ),
        -- Check constraint 2: Active status consistency
        CONSTRAINT chk_active_revoked_logic CHECK (
            (
                is_active = true
                AND revoked_at IS NULL
            )
            OR (
                is_active = false
                AND revoked_at IS NOT NULL
            )
        )
);

-- Indexes cho oauth2_client_secrets
CREATE INDEX IF NOT EXISTS idx_secrets_client_id ON oauth2_client_secrets(client_id);

CREATE INDEX IF NOT EXISTS idx_secrets_is_active ON oauth2_client_secrets(is_active);

CREATE INDEX IF NOT EXISTS idx_secrets_created_by ON oauth2_client_secrets(created_by);

-- Comments
COMMENT ON TABLE oauth2_client_secrets IS 'Lưu trữ client secrets cho OAuth2 clients';

COMMENT ON COLUMN oauth2_client_secrets.id IS 'UUID của secret record';

COMMENT ON COLUMN oauth2_client_secrets.secret_hash IS 'Hash của secret';

COMMENT ON COLUMN oauth2_client_secrets.secret_hint IS 'Gợi ý về secret (VD: ***xyzt)';

-- =====================================================
-- TABLE: oauth2_user_consents
-- =====================================================
CREATE TABLE IF NOT EXISTS oauth2_user_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    client_id UUID NOT NULL,
    granted_scopes TEXT NOT NULL,
    granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- Foreign Keys
    CONSTRAINT fk_consent_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_consent_client FOREIGN KEY (client_id) REFERENCES oauth2_clients(id) ON DELETE CASCADE,
    -- 1 user chỉ có 1 consent record với 1 client
    CONSTRAINT uk_consent_user_client UNIQUE (user_id, client_id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_consents_user_id ON oauth2_user_consents(user_id);

CREATE INDEX IF NOT EXISTS idx_consents_client_id ON oauth2_user_consents(client_id);

-- Trigger updated_at (dùng lại function đã có)
CREATE TRIGGER update_consents_updated_at BEFORE
UPDATE
    ON oauth2_user_consents FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Comments
COMMENT ON TABLE oauth2_user_consents IS 'Lưu trữ consent của user với từng OAuth2 client';

COMMENT ON COLUMN oauth2_user_consents.granted_scopes IS 'Scopes đã được user chấp thuận, phân cách bởi dấu +';

COMMENT ON COLUMN oauth2_user_consents.updated_at IS 'Cập nhật khi user grant thêm scope mới';

-- =====================================================
-- TABLE: email_outbox
-- =====================================================

CREATE TABLE IF NOT EXISTS email_outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_name VARCHAR(100) NOT NULL,
    to_email VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    payload TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    retry_count INT NOT NULL DEFAULT 0,
    last_tried_at TIMESTAMP,
    last_error TEXT,
    sent_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_outbox_status CHECK (status IN ('PENDING', 'SENT', 'FAILED')),
    CONSTRAINT chk_outbox_retry CHECK (retry_count >= 0)
);

CREATE INDEX idx_outbox_status ON email_outbox(status);

CREATE INDEX idx_outbox_created_at ON email_outbox(created_at);

CREATE INDEX idx_outbox_retry_count ON email_outbox(retry_count);

-- Index composite để query PENDING + retry_count < max hiệu quả hơn
CREATE INDEX idx_outbox_pending_retry ON email_outbox(status, retry_count)
WHERE
    status = 'PENDING';

COMMENT ON TABLE email_outbox IS 'Outbox pattern — lưu email chờ gửi, đảm bảo at-least-once delivery';

COMMENT ON COLUMN email_outbox.payload IS 'JSON chứa variables để render Thymeleaf template';

COMMENT ON COLUMN email_outbox.retry_count IS 'Số lần đã thử gửi thất bại';

COMMENT ON COLUMN email_outbox.last_error IS 'Message lỗi của lần thử cuối cùng';

-- =====================================================
-- TABLE: client_invitations
-- =====================================================

CREATE TABLE IF NOT EXISTS client_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL,
    invited_by UUID NOT NULL,
    invitee_email VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL,
    token VARCHAR(64) NOT NULL UNIQUE,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    expires_at TIMESTAMP NOT NULL,
    accepted_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_invitation_client FOREIGN KEY (client_id) REFERENCES oauth2_clients(id) ON DELETE CASCADE,
    CONSTRAINT fk_invitation_inviter FOREIGN KEY (invited_by) REFERENCES users(id)
);

CREATE INDEX idx_invitation_token ON client_invitations(token);

CREATE INDEX idx_invitation_client_id ON client_invitations(client_id);

CREATE INDEX idx_invitation_email ON client_invitations(invitee_email);

CREATE INDEX idx_invitation_status ON client_invitations(status);

CREATE INDEX idx_invitation_expires_at ON client_invitations(expires_at);

-- =====================================================
-- TRIGGER: Auto update updated_at cho users
-- =====================================================
CREATE
OR REPLACE FUNCTION update_updated_at_column() RETURNS TRIGGER AS $$ BEGIN NEW.updated_at = CURRENT_TIMESTAMP;

RETURN NEW;

END;

$$ LANGUAGE plpgsql;

CREATE TRIGGER update_users_updated_at BEFORE
UPDATE
    ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =====================================================
-- INSERT SAMPLE DATA (Optional - for testing)
-- =====================================================
-- Insert admin user
INSERT INTO
    users (
        username,
        name,
        email,
        helper_data,
        mask,
        key_hash,
        role,
        is_active
    )
VALUES
    (
        'admin',
        'System Admin',
        'admin@example.com',
        '{}',
        '',
        'hash123',
        'ADMIN',
        true
    ) ON CONFLICT (username) DO NOTHING;

-- Verify tables created
SELECT
    table_name,
    pg_size_pretty(pg_total_relation_size(quote_ident(table_name))) AS size
FROM
    information_schema.tables
WHERE
    table_schema = 'auth_service'
ORDER BY
    table_name;

-- =====================================================
-- INSERT: oauth2_client (fake data)
-- =====================================================
-- Set search path trước
SET
    search_path TO auth_service,
    public;

-- Lấy ID của admin user để dùng làm created_by
DO $$ DECLARE v_admin_id UUID;

v_client_id UUID;

BEGIN -- Lấy admin user id
SELECT
    id INTO v_admin_id
FROM
    auth_service.users
WHERE
    username = 'admin';

-- Insert oauth2_client
INSERT INTO
    auth_service.oauth2_clients (
        client_id,
        client_name,
        client_type,
        redirect_uri,
        scopes,
        grant_types,
        is_active,
        created_by
    )
VALUES
    (
        'my-web-app-client',
        'My Web Application',
        'CONFIDENTIAL',
        'https://myapp.example.com/callback',
        'openid+profile+email+read:data',
        'authorization_code+refresh_token',
        true,
        v_admin_id
    ) RETURNING id INTO v_client_id;

-- Insert member (admin là OWNER của client này)
INSERT INTO
    auth_service.oauth2_client_members (
        client_id,
        user_id,
        role,
        is_active,
        added_by
    )
VALUES
    (
        v_client_id,
        v_admin_id,
        'OWNER',
        true,
        v_admin_id
    );

-- Insert client secret
INSERT INTO
    auth_service.oauth2_client_secrets (
        client_id,
        secret_hash,
        secret_hint,
        is_active,
        created_by
    )
VALUES
    (
        v_client_id,
        '$2a$12$abc123fakehashabcdefghijklmnopqrstuvwxyz0123456789ABCDE',
        '***xYz9',
        true,
        v_admin_id
    );

RAISE NOTICE 'Created client: %, id: %',
'my-web-app-client',
v_client_id;

END $$;

-- Verify
SELECT
    c.client_id,
    c.client_name,
    c.client_type,
    c.grant_types,
    c.scopes,
    u.username AS created_by,
    m.role AS member_role,
    s.secret_hint
FROM
    auth_service.oauth2_clients c
    JOIN auth_service.users u ON u.id = c.created_by
    JOIN auth_service.oauth2_client_members m ON m.client_id = c.id
    JOIN auth_service.oauth2_client_secrets s ON s.client_id = c.id
WHERE
    c.client_id = 'my-web-app-client';