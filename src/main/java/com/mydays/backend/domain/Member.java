package com.mydays.backend.domain;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "member", indexes = {
        @Index(name = "idx_member_kakao_id", columnList = "kakaoId", unique = true)
})
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // ✅ 카카오 고유 ID(반드시 unique, 카카오 로그인 시 필수)
    @Column(unique = true)
    private Long kakaoId;

    // ✅ 이메일 (로컬/카카오 공용)
    @Column(unique = true)
    private String email;

    // ✅ 닉네임
    private String username;

    // ✅ 로컬 회원용 비밀번호 해시 (카카오 로그인은 null 가능)
    @Column(length = 255)
    private String passwordHash;

    // ✅ 가입 경로 (LOCAL, KAKAO)
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuthProvider provider;
}
