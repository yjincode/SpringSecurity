package com.example.basicsecurityv2.mapper;

import com.example.basicsecurityv2.model.Member;
import com.example.basicsecurityv2.type.Provider;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.Map;


@Mapper
public interface MemberMapper {

    void saved(Member member);
    Member findByUserId(String userId);
    void insertOAuthMember(Member newMember);
    Member findByUserIdAndProvider(@Param("userId") String userId, @Param("oauthProvider") String oauthProvider);
}
