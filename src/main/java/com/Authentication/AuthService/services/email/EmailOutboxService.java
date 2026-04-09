package com.Authentication.AuthService.services.email;

import java.util.Map;

import org.springframework.stereotype.Service;

import com.Authentication.AuthService.entity.EmailOutbox;
import com.Authentication.AuthService.repository.EmailOutboxRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Chỉ có nhiệm vụ LƯU email vào outbox table — gọi trong cùng transaction với
 * business logic.
 * Việc GỬI thực sự do EmailOutboxProcessor đảm nhận.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EmailOutboxService {

    private final EmailOutboxRepository outboxRepository;
    private final ObjectMapper objectMapper;

    public void enqueue(String templateName, String toEmail, String subject, Map<String, Object> variables) {
        try {
            String payload = objectMapper.writeValueAsString(variables);

            EmailOutbox outbox = EmailOutbox.builder()
                    .templateName(templateName)
                    .toEmail(toEmail)
                    .subject(subject)
                    .payload(payload)
                    .build();

            outboxRepository.save(outbox);

        } catch (JsonProcessingException e) {
            // Không nên xảy ra với Map<String, Object> thông thường
            // Throw để rollback transaction — không nên enqueue email với payload lỗi
            throw new IllegalStateException("Failed to serialize email payload", e);
        }
    }
}