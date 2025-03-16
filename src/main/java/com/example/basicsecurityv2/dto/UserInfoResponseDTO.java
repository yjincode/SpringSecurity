package com.example.basicsecurityv2.controller;

import com.example.basicsecurityv2.type.Provider;
import com.example.basicsecurityv2.type.Role;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UserInfoResponseDTO {
    private Long id;
    private String userName;
    private String userId;
    private Role role;
    private Provider provider;
}