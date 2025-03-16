package com.example.basicsecurityv2.controller;

import com.example.basicsecurityv2.config.security.CustomOAuth2User;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/social")
public class SocialUserController {

    @GetMapping("/home")
    public String socialHome(@AuthenticationPrincipal CustomOAuth2User customOAuth2User) {
        if (customOAuth2User == null) {
            return "redirect:/login";
        }
        return "main-page";
    }
}
