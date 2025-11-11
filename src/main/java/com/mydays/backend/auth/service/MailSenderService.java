package com.mydays.backend.auth.service;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class MailSenderService {
    private final JavaMailSender mailSender;

    public MailSenderService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public void sendVerificationCode(String to, String code) {
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(to);
        msg.setSubject("[MyDays] 이메일 인증코드 안내");
        msg.setText("""
                안녕하세요, MyDays 입니다.
                아래 6자리 코드를 %d분 안에 입력해주세요.

                인증코드: %s
                """.formatted(10, code)); // ttl 표기는 properties로 바꿔도 됨
        mailSender.send(msg);
    }
}
