package com.example.basicsecurityv2.config.security;

import com.example.basicsecurityv2.dto.SignInResponseDTO;
import com.example.basicsecurityv2.util.CookieUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication
    ) throws IOException
    {
        CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();

        CookieUtil.addCookie(response, "refreshToken", oAuth2User.getRefreshToken(), 7 * 24 * 60 * 60);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        SignInResponseDTO build = SignInResponseDTO.builder()
                .success(true)
                .token(oAuth2User.getJwtToken())
                .build();

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(build));
    }
}
