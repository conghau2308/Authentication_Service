// package com.Authentication.AuthService.scheduler;

// import java.time.LocalDateTime;

// import org.springframework.scheduling.annotation.Scheduled;
// import org.springframework.stereotype.Component;
// import org.springframework.transaction.annotation.Transactional;

// import com.Authentication.AuthService.repository.ClientInvitationRepository;

// import lombok.RequiredArgsConstructor;
// import lombok.extern.slf4j.Slf4j;

// @Component
// @RequiredArgsConstructor
// @Slf4j
// public class InvitationExpiryScheduler {

//     private final ClientInvitationRepository invitationRepository;

//     // Chạy mỗi ngày lúc 2:00 AM — bulk update thay vì load từng entity
//     @Scheduled(cron = "0 0 2 * * *")
//     @Transactional
//     public void expireOverdueInvitations() {
//         int count = invitationRepository.bulkExpireInvitations(LocalDateTime.now());
//         if (count > 0) {
//             log.info("Expired {} overdue invitations", count);
//         }
//     }
// }