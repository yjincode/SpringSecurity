package com.example.basicsecurityv2.config.jwt;

import com.example.basicsecurityv2.model.Member;
import com.example.basicsecurityv2.type.Role;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenProvider {

    private final JwtProperties jwtProperties;

    public String generateToken(Member member, Duration expiredAt) {
        Date now = new Date();
        return makeToken(
                member,
                new Date( now.getTime() + expiredAt.toMillis() )
        );
    }

    public Member getTokenDetails(String token) {
        Claims claims = getClaims(token);

        return Member.builder()
                .id(claims.get("id", Long.class))
                .userId(claims.getSubject())
                .userName(claims.get("userName", String.class))
                .role(
                        Role.valueOf(claims.get("role", String.class))
                )
                .build();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);

        // Claims에서 역할을 추출하고, GrantedAuthority로 변환
        List<GrantedAuthority> authorities = Collections.singletonList(
                new SimpleGrantedAuthority(claims.get("role", String.class))
        );
        // UserDetails 객체 생성
        UserDetails userDetails = new User(claims.getSubject(), "", authorities);

        // UsernamePasswordAuthenticationToken 생성
        return new UsernamePasswordAuthenticationToken(userDetails, token, authorities);
    }

    public int validToken(String token) {
        try {
            getClaims(token);
            return 1;
        } catch (ExpiredJwtException e) {
            // 토큰이 만료된 경우
            log.info("Token이 만료되었습니다.");
            return 2;
        } catch (Exception e) {
            // 복호화 과정에서 에러가 나면 유효하지 않은 토큰
            System.out.println("Token 복호화 에러 : " + e.getMessage());
            return 3;
        }
    }

    private String makeToken(Member member, Date expired) {
        Date now = new Date();

       return Jwts.builder()
               .setHeaderParam(Header.TYPE, Header.JWT_TYPE)
               .setIssuer(jwtProperties.getIssuer())
               .setIssuedAt(now)
               .setExpiration(expired)
               .claim("id", member.getId())
               .claim("role", member.getRole().name())
               .claim("userName", member.getUserName())
               .setSubject(member.getUserId())
               .signWith(getSecretKey(), SignatureAlgorithm.HS512)
               .compact();
    }

    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSecretKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private SecretKey getSecretKey() {
        byte[] keyBytes = Base64.getDecoder().decode(jwtProperties.getSecretKey());
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
