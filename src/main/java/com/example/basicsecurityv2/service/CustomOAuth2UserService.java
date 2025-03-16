package com.example.basicsecurityv2.service;

import com.example.basicsecurityv2.config.jwt.TokenProvider;
import com.example.basicsecurityv2.config.security.CustomOAuth2User;
import com.example.basicsecurityv2.mapper.MemberMapper;
import com.example.basicsecurityv2.model.Member;
import com.example.basicsecurityv2.type.Provider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final MemberMapper memberMapper;
    private final TokenProvider tokenProvider;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        Map<String, Object> response = (Map<String, Object>) oAuth2User.getAttributes().get("response");
        String userId = (String) response.get("id");
        String name = (String) response.get("name");

        Member existingMember = memberMapper.findByUserIdAndProvider(userId, Provider.naver.name());

        if (existingMember == null) {
            Member newMember = Member.builder()
                    .userId(userId)  // 네이버에서 받은 고유 ID 저장
                    .userName(name)  // 네이버에서 가져온 유저 이름
                    .oauthProvider(Provider.naver)  // ✅ 네이버 로그인 계정임을 표시
                    .build();

            memberMapper.insertOAuthMember(newMember);
            existingMember = newMember;  // 이후 처리 위해 변수 업데이트
        }
        // ✅ JWT 발급 (기존 사용자든 신규 회원이든)
        String accessToken = tokenProvider.generateToken(existingMember,  Duration.ofHours(2));
        String refreshToken = tokenProvider.generateToken(existingMember, Duration.ofDays(2));

        // ✅ 사용자 정보와 JWT를 반환할 CustomOAuth2User 객체 생성
        return new CustomOAuth2User(existingMember, accessToken, refreshToken);
    }

}
