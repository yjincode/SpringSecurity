package com.example.basicsecurityv2.controller;

import com.example.basicsecurityv2.config.jwt.TokenProvider;
import com.example.basicsecurityv2.config.security.CustomUserDetails;
import com.example.basicsecurityv2.dto.SignInRequestDTO;
import com.example.basicsecurityv2.dto.SignInResponseDTO;
import com.example.basicsecurityv2.dto.SignUpRequestDTO;
import com.example.basicsecurityv2.dto.SignUpResponseDTO;
import com.example.basicsecurityv2.model.Member;
import com.example.basicsecurityv2.service.MemberService;
import com.example.basicsecurityv2.type.Role;
import com.example.basicsecurityv2.util.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

@RestController
@RequiredArgsConstructor
public class MemberApiController {

    private final MemberService memberService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final AuthenticationManager authenticationManager;
    private final TokenProvider tokenProvider;

    @PostMapping("/join")
    public SignUpResponseDTO join(@RequestBody SignUpRequestDTO signUpRequestDTO) {
        return memberService.signUpIfUsernameAvailable(signUpRequestDTO.toMember(bCryptPasswordEncoder));
    }

    @PostMapping("/login")
    public SignInResponseDTO login(@RequestBody SignInRequestDTO signInRequestDTO,
                                   HttpServletResponse response) {
        try {
            Authentication authenticate = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            signInRequestDTO.getUserId(),
                            signInRequestDTO.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authenticate);

            Member member = ((CustomUserDetails) authenticate.getPrincipal()).getMember();

            String accessToken = tokenProvider.generateToken(member, Duration.ofHours(2));
            String refreshToken = tokenProvider.generateToken(member, Duration.ofDays(2));
            CookieUtil.addCookie(response, "refreshToken", refreshToken, 7 * 24 * 60 * 60);

            return SignInResponseDTO.builder()
                    .success(true)
                    .token(accessToken)
                    .build();
        }catch (BadCredentialsException e) {
            return SignInResponseDTO.builder()
                    .success(false)
                    .build();
        }
}

    @PostMapping("/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        CookieUtil.deleteCookie(request, response, "refreshToken");
    }

    @GetMapping("/user/info")
    public UserInfoResponseDTO getUserInfo(HttpServletRequest request) {
        Member member = (Member) request.getAttribute("member");
        return UserInfoResponseDTO.builder()
                .id(member != null ? member.getId() : 0L)  // 기본값 설정
                .userName(member != null ? member.getUserName() : "Unknown")
                .userId(member != null ? member.getUserId() : "N/A")
                .role(member != null ? member.getRole() : Role.ROLE_USER)
                .build();
    }
}