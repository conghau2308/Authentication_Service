package com.Authentication.AuthService;

import java.util.TimeZone;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.github.cdimascio.dotenv.Dotenv;

@SpringBootApplication
public class AuthServiceApplication {

	public static void main(String[] args) {
		// Phải set trước khi bất cứ thứ gì khởi tạo — JDBC driver gửi JVM timezone
		// trong startup handshake với PostgreSQL; "Asia/Saigon" không được PG17 nhận.
		TimeZone.setDefault(TimeZone.getTimeZone("Asia/Ho_Chi_Minh"));

		Dotenv dotenv = Dotenv.configure()
				.ignoreIfMissing()
				.load();
		dotenv.entries().forEach(entry -> System.setProperty(entry.getKey(), entry.getValue()));
		SpringApplication.run(AuthServiceApplication.class, args);
	}

}
