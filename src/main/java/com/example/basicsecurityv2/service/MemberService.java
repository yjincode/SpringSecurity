package com.example.basicsecurityv2.service;

import com.example.basicsecurityv2.dto.SignUpResponseDTO;
import com.example.basicsecurityv2.mapper.MemberMapper;
import com.example.basicsecurityv2.model.Member;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberMapper memberMapper;

    public SignUpResponseDTO signUpIfUsernameAvailable(Member member) {
        if (!StringUtils.hasText(member.getUserId()) || !StringUtils.hasText(member.getPassword()) || !StringUtils.hasText(member.getUserName())) {
            return SignUpResponseDTO.builder()
                            .success(false)
                            .message("필드값을 전부 입력해주세요")
                            .build();
        }

        Member byUserId = memberMapper.findByUserId(member.getUserId());
        if (byUserId == null) {
            memberMapper.saved(member);
            return SignUpResponseDTO.builder()
                    .success(true)
                    .message("회원가입이 성공했습니다.\n로그인해주세요.")
                    .build();
        } else {
            return SignUpResponseDTO.builder()
                    .success(false)
                    .message("사용할수 없는 아이디입니다.")
                    .build();
        }
    }

}
