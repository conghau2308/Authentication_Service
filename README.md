# WiFaKey - Authentication & Authorization Service

![Java](https://img.shields.io/badge/Java-17%2B-orange?style=flat-square&logo=openjdk)
![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.x-green?style=flat-square&logo=springboot)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue?style=flat-square&logo=postgresql)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

**WiFaKey Backend** là dịch vụ lõi (Authorization Server) cung cấp khả năng xác thực và ủy quyền theo chuẩn **OAuth2.0** và **OpenID Connect (OIDC)**. Dự án được xây dựng trên nền tảng Java Spring Boot, phục vụ như một trung tâm bảo mật cho các ứng dụng trong hệ sinh thái.

---

## 🔗 Hệ sinh thái dự án (Project Ecosystem)

Để chạy toàn bộ kịch bản demo (OAuth Flow), bạn cần clone và khởi chạy các dự án vệ tinh dưới đây (khuyến khích checkout nhánh `main` hoặc `conghau`):

| Thành phần                             | Repository Link                                                                                 | Mô tả                                          |
| :------------------------------------- | :---------------------------------------------------------------------------------------------- | :--------------------------------------------- |
| **1. Auth Portal (Frontend)**          | [Auth_Developer_Portal](https://github.com/conghau2308/Auth_Developer_Portal.git)               | Trang quản lý user & đăng ký ứng dụng Client   |
| **2. Ecommerce API (Resource Server)** | [Ecommerce_Backend_OAuth](https://github.com/conghau2308/Ecommerce_Backend_OAuth_WiFaKey.git)   | Backend bán hàng mẫu (được bảo vệ bởi WiFaKey) |
| **3. Ecommerce App (Client)**          | [Ecommerce_Frontend_OAuth](https://github.com/conghau2308/Ecommerce_Frontend_OAuth_WiFaKey.git) | Web bán hàng mẫu (Demo luồng đăng nhập SSO)    |

---

## 🛠 Yêu cầu hệ thống

Trước khi bắt đầu, hãy đảm bảo môi trường development của bạn đã sẵn sàng:

- **Java Development Kit (JDK):** Version 17 trở lên.
- **Node.js:** (Dành cho các dự án Frontend).
- **Cơ sở dữ liệu:**
  - MySQL (Cho WiFaKey Service).
  - PostgreSQL (Cho Ecommerce Demo Backend).
- **Docker:** (Khuyến nghị để chạy nhanh các database).

---

## 🚀 Cài đặt & Cấu hình WiFaKey (Core)

### 1. Cấu hình Database (MySQL)

WiFaKey sử dụng MySQL. Bạn cần tạo database và chạy script khởi tạo trước khi start app.

1.  Tạo database trống tên: `wifakey_db` (hoặc tên tùy chọn).
2.  Chạy script SQL nằm trong thư mục: `src/main/resources/sql/init_schema.sql` (hoặc đường dẫn tương ứng trong source code).
3.  Cập nhật file `src/main/resources/application.properties`:

```properties
spring.datasource.url=
spring.datasource.username=root
spring.datasource.password=YOUR_PASSWORD
# Các cấu hình JPA/Hibernate khác...
```
