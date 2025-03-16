package com.example.basicsecurityv2.service;

import com.example.basicsecurityv2.config.security.CustomUserDetails;
import com.example.basicsecurityv2.mapper.MemberMapper;
import com.example.basicsecurityv2.model.Member;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserDetailServiceImpl implements UserDetailsService {

    private final MemberMapper memberMapper;

    @Override
    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {

        Member member = memberMapper.findByUserId(userId);
        if (member == null) {
            throw new UsernameNotFoundException(userId + " not found");
        }

        return CustomUserDetails.builder()
                .member(member)
                .roles(List.of(member.getRole().name()))
                .build();
    }
}

