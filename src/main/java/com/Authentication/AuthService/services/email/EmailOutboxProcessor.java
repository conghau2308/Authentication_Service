package com.Authentication.AuthService.services.email;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import com.Authentication.AuthService.entity.EmailOutbox;
import com.Authentication.AuthService.enums.EmailStatus;
import com.Authentication.AuthService.repository.EmailOutboxRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Chạy nền theo lịch — đọc email_outbox và gửi thực sự.
 * Tách hoàn toàn khỏi business transaction.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EmailOutboxProcessor {

    private final EmailOutboxRepository outboxRepository;
    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;
    private final ObjectMapper objectMapper;

    @Value("${spring.mail.username:flyingbookstore999@gmail.com}")
    private String senderEmail;

    @Value("${app.mail.sender-name:Wifakey IdP}")
    private String senderName;

    @Value("${app.mail.max-retry:3}")
    private int maxRetry;

    @Value("${app.mail.batch-size:20}")
    private int batchSize;

    // fixedDelay: đợi lần trước xong hẳn rồi mới tính 30s tiếp theo
    // tránh overlap nếu batch xử lý lâu hơn interval
    @Scheduled(fixedDelayString = "${app.mail.process-interval-ms:30000}")
    @Transactional
    public void processOutbox() {
        List<EmailOutbox> batch = outboxRepository.findPendingBatch(
                EmailStatus.PENDING,
                maxRetry,
                PageRequest.of(0, batchSize));

        if (batch.isEmpty())
            return;

        log.debug("Processing {} pending emails", batch.size());

        for (EmailOutbox outbox : batch) {
            try {
                sendEmail(outbox);
                outbox.markSent();
                log.info("Email sent successfully: id={} to={}", outbox.getId(), outbox.getToEmail());

            } catch (Exception e) {
                outbox.recordFailure(e.getMessage(), maxRetry);

                if (outbox.getStatus() == EmailStatus.FAILED) {
                    log.error("Email permanently failed after {} retries: id={} to={}",
                            maxRetry, outbox.getId(), outbox.getToEmail());
                } else {
                    log.warn("Email send failed (retry {}/{}): id={} error={}",
                            outbox.getRetryCount(), maxRetry, outbox.getId(), e.getMessage());
                }
            }
        }
        // @Transactional flush tất cả update cuối batch — không cần save từng cái
    }

    private void sendEmail(EmailOutbox outbox) throws Exception {
        // Deserialize payload JSON → Map
        Map<String, Object> variables = objectMapper.readValue(
                outbox.getPayload(),
                new TypeReference<Map<String, Object>>() {
                });

        if (variables.get("expiresAt") instanceof String expiresAtStr) {
            variables.put("expiresAt", LocalDateTime.parse(expiresAtStr));
        }

        // Build Thymeleaf context
        Context ctx = new Context();
        ctx.setVariables(variables);

        String html = templateEngine.process(outbox.getTemplateName(), ctx);

        // Tạo và gửi email
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        helper.setFrom(senderEmail, senderName);
        helper.setTo(outbox.getToEmail());
        helper.setSubject(outbox.getSubject());
        helper.setText(html, true);

        mailSender.send(message);
    }
}