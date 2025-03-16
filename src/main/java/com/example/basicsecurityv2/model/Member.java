package com.example.basicsecurityv2.model;


import com.example.basicsecurityv2.type.Provider;
import com.example.basicsecurityv2.type.Role;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class Member {
    private long id;
    private String userId;
    private String password;
    private String userName;
    private Role role;
    private Provider oauthProvider;
}