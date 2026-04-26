# WiFaKey — Biometric OAuth 2.0 & OpenID Connect Server

![Java](https://img.shields.io/badge/Java-17%2B-orange?style=flat-square&logo=openjdk)
![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.x-green?style=flat-square&logo=springboot)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue?style=flat-square&logo=postgresql)
![Redis](https://img.shields.io/badge/Redis-7.x-red?style=flat-square&logo=redis)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

**WiFaKey** là Authorization Server theo chuẩn **OAuth 2.0** và **OpenID Connect (OIDC)**, tích hợp xác thực sinh trắc học bằng **khuôn mặt (Face Biometric)**. Thay vì mật khẩu truyền thống, WiFaKey sử dụng nhận diện khuôn mặt như phương thức định danh chính — nhanh hơn, an toàn hơn, và không cần nhớ password.

🌐 **Developer Portal:** [https://auth-developer-portal.vercel.app](https://auth-developer-portal.vercel.app/home)

---

## ✨ Tính năng nổi bật

- 🔐 **Face Biometric Authentication** — Đăng nhập bằng khuôn mặt, không cần mật khẩu
- 🛡️ **OAuth 2.0 Authorization Server** — Hỗ trợ Authorization Code Flow với PKCE
- 🪪 **OpenID Connect (OIDC)** — Cung cấp ID Token và UserInfo endpoint chuẩn
- 👨‍💻 **Developer Portal** — Đăng ký và quản lý OAuth Client ngay trên giao diện web
- 🔑 **Consent Management** — Người dùng kiểm soát toàn bộ ứng dụng đã được cấp quyền
- 👤 **User Profile Management** — Quản lý thông tin cá nhân và bảo mật tài khoản
- ⚡ **Redis Caching** — Cache token, session và dữ liệu xác thực để tăng hiệu năng
- 🚦 **Rate Limiting** — Bảo vệ API khỏi brute-force và DDoS theo IP và Client ID

---

## 🏗️ Kiến trúc hệ thống

```
┌─────────────────────────────────────────────────────────┐
│                    Client Applications                   │
│            (Web App / Mobile App / Third-party)          │
└──────────────────────────┬──────────────────────────────┘
                           │ OAuth 2.1 / OIDC
                           ▼
┌─────────────────────────────────────────────────────────┐
│                WiFaKey Authorization Server              │
│                                                          │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │  OAuth 2.0  │  │     OIDC     │  │ Face Biometric │  │
│  │  Endpoints  │  │  Endpoints   │  │    Engine      │  │
│  └─────────────┘  └──────────────┘  └───────────────┘  │
│                                                          │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │    Redis     │  │  PostgreSQL  │  │  Rate Limiter  │  │
│  │   (Cache)    │  │     (DB)     │  │  (Bucket4j)    │  │
│  └─────────────┘  └──────────────┘  └───────────────┘  │
└─────────────────────────────────────────────────────────┘
                           │ Access Token / JWT
                           ▼
┌─────────────────────────────────────────────────────────┐
│                    Resource Servers                       │
│               (Ecommerce API, Other APIs...)              │
└─────────────────────────────────────────────────────────┘
```

---

## 🔗 Project Ecosystem

WiFaKey hoạt động như trung tâm bảo mật cho toàn bộ hệ sinh thái. Để chạy demo đầy đủ, clone thêm các dự án sau:

| Thành phần | Repository | Mô tả |
|:-----------|:-----------|:------|
| **Auth Developer Portal** | [Auth_Developer_Portal](https://github.com/conghau2308/Auth_Developer_Portal.git) | Trang quản lý user, client, consent |
| **Ecommerce API** | [Ecommerce_Backend_OAuth](https://github.com/conghau2308/Ecommerce_Backend_OAuth_WiFaKey.git) | Resource Server mẫu được bảo vệ bởi WiFaKey |
| **Ecommerce App** | [Ecommerce_Frontend_OAuth](https://github.com/conghau2308/Ecommerce_Frontend_OAuth_WiFaKey.git) | Client App mẫu — demo luồng SSO |

---

## 📋 OAuth 2.1 Authorization Code Flow

```
User               Client App           WiFaKey IdP          Resource Server
 │                     │                      │                      │
 │── Click "Login" ──▶│                      │                      │
 │                     │─── Authorization ──▶│                      │
 │                     │       Request        │                      │
 │◀────────────────────│◀── Redirect to ─────│                      │
 │                          Login Page        │                      │
 │──── Face Scan ───────────────────────────▶│                      │
 │                                            │── Verify Biometric   │
 │                                            │── Issue Auth Code    │
 │◀───────────────────────────────────────────│                      │
 │─ Redirect with Code▶│                     │                      │
 │                     │─── Exchange Code ───▶│                      │
 │                     │     for Token        │── Issue Access Token │
 │                     │◀────────────────────│                      │
 │                     │──── API Request ──────────────────────────▶│
 │                     │◀─── Protected Data ───────────────────────│
```

---

## 🔌 API Endpoints

### OAuth 2.0 / OIDC

| Method | Endpoint | Mô tả |
|--------|----------|-------|
| `GET` | `/oauth2/authorize` | Khởi tạo Authorization Flow |
| `POST` | `/oauth2/token` | Đổi Authorization Code lấy Token |
| `POST` | `/oauth2/revoke` | Thu hồi Access / Refresh Token |
| `POST` | `/oauth2/introspect` | Kiểm tra trạng thái token |
| `GET` | `/oauth2/userinfo` | Lấy thông tin người dùng (OIDC) |
| `GET` | `/.well-known/openid-configuration` | OIDC Discovery Endpoint |
| `GET` | `/.well-known/jwks.json` | Public key để verify JWT |

### Authentication

| Method | Endpoint | Mô tả |
|--------|----------|-------|
| `POST` | `/api/auth/register` | Đăng ký tài khoản mới |
| `POST` | `/api/auth/login` | Đăng nhập bằng khuôn mặt |
| `POST` | `/api/auth/refresh` | Làm mới Access Token |
| `POST` | `/api/auth/logout` | Đăng xuất |

### User Management

| Method | Endpoint | Mô tả |
|--------|----------|-------|
| `GET` | `/api/users/me` | Lấy thông tin profile |
| `PUT` | `/api/users/me` | Cập nhật thông tin cá nhân |
| `GET` | `/api/users/me/consents` | Danh sách app đã được cấp quyền |
| `DELETE` | `/api/users/me/consents/{clientId}` | Thu hồi quyền của một app |

### Developer — Client Management

| Method | Endpoint | Mô tả |
|--------|----------|-------|
| `GET` | `/api/clients` | Danh sách OAuth Client của developer |
| `POST` | `/api/clients` | Tạo OAuth Client mới |
| `GET` | `/api/clients/{clientId}` | Chi tiết một Client |
| `PUT` | `/api/clients/{clientId}` | Cập nhật thông tin Client |
| `DELETE` | `/api/clients/{clientId}` | Xóa Client |
| `POST` | `/api/clients/{clientId}/secret/rotate` | Xoay Client Secret |

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Language** | Java 17+ |
| **Framework** | Spring Boot 3.x, Spring Security, Spring Data JPA |
| **Database** | PostgreSQL 15 |
| **Cache** | Redis 7.x |
| **Authentication** | JWT (RS256), Face Biometric |
| **Rate Limiting** | Bucket4j |
| **Build Tool** | Maven |
| **Containerization** | Docker, Docker Compose |

---

## ⚙️ Cài đặt & Chạy dự án

### Yêu cầu hệ thống

- Java 17+
- Docker & Docker Compose
- PostgreSQL 15
- Redis 7.x

### 1. Clone dự án

```bash
git clone https://github.com/dnhthnhnee/WiFaKey.git
cd WiFaKey
```

### 2. Khởi động PostgreSQL & Redis bằng Docker

```bash
docker compose up -d
```

### 3. Cấu hình `application.properties`

```properties
# Database
spring.datasource.url=jdbc:postgresql://localhost:5432/wifakey_db
spring.datasource.username=postgres
spring.datasource.password=YOUR_PASSWORD

# Redis
spring.data.redis.host=localhost
spring.data.redis.port=6379

# JWT (RS256)
jwt.private-key=classpath:keys/private.pem
jwt.public-key=classpath:keys/public.pem
jwt.access-token-expiry=900        # 15 phút (giây)
jwt.refresh-token-expiry=2592000   # 30 ngày (giây)

# Face Biometric Service
biometric.service.url=http://localhost:8000
```

### 4. Khởi tạo Database Schema

```bash
psql -U postgres -d wifakey_db -f src/main/resources/sql/init_schema.sql
```

### 5. Chạy ứng dụng

```bash
./mvnw spring-boot:run
```

Server khởi động tại: `http://localhost:8080`

---

## 🐳 Chạy toàn bộ hệ thống bằng Docker Compose

```bash
docker compose up --build
```

| Service | URL |
|---------|-----|
| WiFaKey Auth Server | `http://localhost:8080` |
| Developer Portal | `http://localhost:3000` |
| PostgreSQL | `localhost:5432` |
| Redis | `localhost:6379` |

---

## 📁 Cấu trúc thư mục

```
WiFaKey/
├── src/main/java/com/Authentication/AuthService/
│   ├── annotation/          # Custom annotations (@RateLimit, ...)
│   ├── aspect/              # AOP aspects (RateLimitAspect, ...)
│   ├── config/              # Spring Security, Redis, Cookie config
│   ├── controller/          # REST Controllers
│   ├── dto/                 # Request / Response DTOs
│   │   ├── request/
│   │   └── response/
│   ├── entity/              # JPA Entities
│   ├── exception/           # Global exception handling
│   │   └── business/
│   ├── filter/              # Servlet Filters (JwtAuthFilter, ...)
│   ├── repository/          # Spring Data JPA Repositories
│   └── services/            # Business Logic
│       └── auth/
├── src/main/resources/
│   ├── keys/                # RSA key pair cho JWT signing
│   ├── sql/                 # Database init scripts
│   └── application.properties
├── docker-compose.yml
└── pom.xml
```

---

## 🔒 Bảo mật

- **JWT RS256** — Token ký bằng RSA private key, các Resource Server verify bằng public key qua JWKS endpoint
- **Face Biometric** — Khuôn mặt được hash trên thiết bị, không lưu trữ ảnh gốc trên server
- **PKCE** — Bắt buộc trong Authorization Code Flow để chống code interception attack
- **Rate Limiting** — Giới hạn request theo IP và Client ID bằng Bucket4j (Token Bucket algorithm)
- **Redis Token Blacklist** — Token đã revoke được lưu vào blacklist, chặn ngay lập tức dù chưa hết hạn
- **Refresh Token Rotation** — Mỗi lần refresh cấp token mới và vô hiệu hóa token cũ

---

## 🌐 Developer Portal

Giao diện web để quản lý tài khoản và OAuth Client.

🔗 **Live:** [https://auth-developer-portal.vercel.app](https://auth-developer-portal.vercel.app/home)

**Dành cho người dùng:**
- Xem và chỉnh sửa thông tin profile
- Quản lý danh sách ứng dụng đã cấp quyền (Consent Management)
- Thu hồi quyền truy cập của bất kỳ ứng dụng nào bất cứ lúc nào

**Dành cho Developer (role: developer):**
- Đăng ký OAuth Client mới
- Cấu hình Redirect URIs, Scopes, Grant Types
- Xoay Client Secret khi cần thiết
- Quản lý toàn bộ vòng đời của Client

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.