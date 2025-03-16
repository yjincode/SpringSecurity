# SpringSecurity

<aside>
💡

### Spring Security 의 개념

</aside>

<br/><br/>

[*Spring Security는 인증](https://docs.spring.io/spring-security/reference/features/authentication/index.html) , [권한 부여](https://docs.spring.io/spring-security/reference/features/authorization/index.html) 및 [일반적인 공격에 대한 보호를](https://docs.spring.io/spring-security/reference/features/exploits/index.html) 제공하는 프레임워크입니다 . _ 공식*

<br/><br/><br/><br/>


1. **spring security 는**

Spring application 에 보안을 적용하는 과정을 크게 간소화시킨 프레임워크이다

스프링 애플리케이션 에서 애플리케이션 수준의 보안을 구현할 때 가장 우선적인 선택이며 

인증, 권한 부여 및 일반적인 공격에 대한 방어를 구현하는 세부적인 맞춤 구성방법을 제공한다

- 애플리케이션 수준의 보안이란?
    
    애플리케이션 수준의 보안은
    
    **소프트웨어 개발 프로세스에서 애플리케이션의 취약점을 찾아 수정하고 막는 보안 작업**
    
    을 말합니다. 이를 애플리케이션 보안(AppSec)이라고도 합니다.
    
    **애플리케이션 수준의 보안은 다음과 같은 목표를 달성하기 위해 이루어집니다.**
    
    - 사이버 범죄자들이 애플리케이션의 취약점을 악용하지 못하도록 방지
    - 기업의 생태계, 민감한 데이터, 인증정보, 기타 디지털 자산을 보호
    - 웹 앱의 원활한 작동을 유지
    - 사이버 기물 파손, 데이터 도난, 비윤리적 경쟁 등 부정적인 결과로부터 기업을 보호
    
    **애플리케이션 수준의 보안을 위해서는 다음과 같은 방법을 사용할 수 있습니다.**
    
    - 보안을 개발 프로세스와 지속적으로 통합하는 애플리케이션 보안 테스트 조정
    - 지속적인 모니터링, 빈번한 테스트, 신속한 취약성 수정
    - OWASP(Open Web Application Security Project)에서 확인된 위협으로부터 보호하는 기능을 사용

스프링 시큐리티의 보안을적용하는 과정은 스프링 컨텍스트의 관리로 시작한다

개발자는 스프링 컨텍스트에 빈을 정의해 프레임워크가 지정된 구성을 바탕으로

빈을 관리하도록 한다. 이러한 구성은 *@***어노테이션** 만으로 작성한다.

spring security 의 개념을 현실의 비유를 들자면

집의 출입을 통제하는 방법을 비교할 수 있다.

- 현관 깔개 밑에 열쇠를 숨겨두는가?
- 현관문 열쇠가 있기는 한가? 등등

출입 보안을 구성하는 방법

- 다양한 경보 시스템을 갖췄는가?
- 좌물쇠가 채워져있는가 등등

애플리케이션 또한 같은 개념이 적용되며 이기능을 개발하는데 spring security 가 도움 된다

spring security 를 어떻게 이용하면 좋을까?

일반적으로 애플리케이션 수준에서 가장 흔한 보안의 활용 사례는

- 누가 작업을 수행할 수 있는지, 특정 데이터를 이용할 수 있는지를 결정
- 구성을 기반으로 요청을 가로채고 권한을 가진 사용자만 보호된 리소스에 접근
- 개발자는 원하는 것을 정확하게 수행하도록 구성요소를 구성한다

*스프링 시큐리티는 시스템의 보안문제들을 여러 방법으로 해결할 수있는 구성 요소를 제공하지만*

*어떤 부분을 구성해야하는지 알고 시스템에서 이를 설정하는것은 개발자의 몫이다!  _ 당연한말*

<br/><br/><br/><br/>

1. **소프트웨어 보안이란?**

현재의 소프트웨어는 상당부분이 민감한 정보일 수 있는 대량의 데이터를 관리한다.

유출됐을 때 위험성이 높은 정보는(예를들면 신용 카드 정보, 사용자의 주소, 비밀번호 등등)

더욱 중요하게 보안을 고려해야 한다. 애플리케이션은 이러한 정보에 접근, 변경 또는

가로챌 기회가 없게해야 하며 의도된 사용자가 이외의 대상은 어떤 식으로든 데이터와 상호작용

할 수 없게 해야한다 이것이 광범위하게 표현한 보안의 의미다.

*보안은 뚫릴 수 밖에 없다 그러니 보안을 생각할 때는 악성사용자가 보안을 뚫고 들어왔을때를*

*염두해 두고 어떤식으로 대처하고 데이터를 지킬 것인가 에 대한 고민을 해야한다*

<br/><br/><br/><br/>


# Spring Security 구조 & OAuth2 활용한 네이버 아이디 로그인

<aside>
💡

### **Spring Security Architecture** ( 스프링 시큐리티의 구조 )

</aside>
![Image](https://raw.githubusercontent.com/yjincode/SpringSecurity/main/assets/image.png)
위 경로는 Spring Security 아키텍처

### **Spring Security의 주요 컴포넌트**

Spring Security의 인증(Authentication)과 인가(Authorization)는 다음과 같은 주요 컴포넌트로 이루어져 있다
| 컴포넌트 | 역할 |
|---------|---------|
| `SecurityFilterChain` | 요청을 가로채고 여러 필터를 실행하는 보안 필터 체인 |
| `UsernamePasswordAuthenticationFilter` | 로그인 요청을 처리하는 필터 |
| `AuthenticationManager` | 인증 요청을 위임하는 관리자 |
| `UserDetailsService` | DB에서 사용자 정보를 조회하는 서비스 |
| `PasswordEncoder` | 비밀번호 암호화 및 비교 |
| `SecurityContextHolder` | 인증 정보를 저장하는 컨텍스트 |
<br/>
<br/>
### **Spring Security 로그인 과정 **
우선 Spring Security에서 가장 기본적인 **폼 로그인 (Form Login)** 방식
- 1. 사용자가 ID, PW 입력 후 로그인 버튼 클릭 (POST /login 요청)
- 2. Spring Security가 로그인 요청을 가로챔 (UsernamePasswordAuthenticationFilter)
- 3. 입력된 ID & PW를 DB에서 조회 (UserDetailsService)
- 4. 비밀번호 일치 여부 확인 (PasswordEncoder)
- 5. 인증 성공하면 사용자 정보를 저장 (SecurityContextHolder)
- 6. 로그인 성공 후 세션 기반 인증 (Session Cookie 발급) → 이후 요청에서 인증 정보를 활용

위 방식은 기본적으로 세션을 이용하는 방식이며, 브라우저가 세션 쿠키를 저장하여 인증을 유지함

3️⃣ JWT를 활용한 로그인 과정

Spring Security의 기본 폼 로그인이 아닌, JWT(Json Web Token) 기반 로그인 방식을 적용할 수도 있어요. JWT 방식은 세션을 사용하지 않고, 토큰을 이용해 인증을 유지하는 방식이에요.

✅ JWT 로그인 과정

사용자가 ID, PW 입력 후 로그인 버튼 클릭 (POST /login 요청)

Spring Security가 로그인 요청을 가로챔 (UsernamePasswordAuthenticationFilter)

입력된 ID & PW를 DB에서 조회 (UserDetailsService)

비밀번호 일치 여부 확인 (PasswordEncoder)

인증 성공하면 JWT AccessToken, RefreshToken을 생성하여 응답

이후 사용자는 API 요청 시 AccessToken을 헤더에 포함하여 요청

서버에서는 JWT 필터(JwtAuthenticationFilter)를 통해 AccessToken 검증

인증이 유효하면 요청을 정상 처리, 만료되면 RefreshToken을 이용해 새 AccessToken 발급

📌 JWT 방식은 서버에 세션을 저장하지 않고, 클라이언트가 토큰을 관리한다는 점이 핵심이에요!

Spring Security는 마치 회사의 출입 시스템과 같아요.
- 회사 출입문에서 신분증을 확인 (사용자 인증)
- 특정 부서만 출입 가능한 공간 제한 (인가)
- 외부인이 함부로 들어오지 못하도록 보안 설정 (공격 방어)

---

## 2️⃣ Spring Security 설정 예제 (`SecurityConfig.java`)
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable() // CSRF 보호 비활성화 (테스트용)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/register").permitAll() // 로그인, 회원가입은 모두 허용
                .anyRequest().authenticated() // 나머지는 로그인해야 접근 가능
            )
            .formLogin().loginPage("/login") // 로그인 페이지 지정
            .and()
            .logout().logoutUrl("/logout"); // 로그아웃 설정
        return http.build();
    }
}
```
✅ **핵심 요약:** 위 코드에서 `/login`, `/register`는 인증 없이 접근할 수 있고, 나머지 페이지는 로그인해야 접근할 수 있어요!

---

## 3️⃣ 네이버 로그인 (OAuth2) 쉽게 이해하기

### ✅ **OAuth2 로그인 과정 (한눈에 보기)**
1. 사용자가 **네이버 로그인 버튼 클릭** → 네이버 로그인 페이지로 이동
2. 네이버에서 로그인 후 **Authorization Code 발급**
3. Spring Boot가 Authorization Code를 받아 **네이버 서버에 Access Token 요청**
4. 네이버가 **Access Token 발급** → Spring Boot가 사용자 정보 요청
5. **네이버에서 사용자 정보 응답** (이름, 이메일 등) → 로그인 완료 🎉

이제 코드를 통해 네이버 로그인을 설정해볼게요!

### ✅ **네이버 로그인 설정 (`application.yml`)**
```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          naver:
            client-id: 네이버_CLIENT_ID
            client-secret: 네이버_CLIENT_SECRET
            client-authentication-method: post
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/login/oauth2/code/naver"
            scope: name, email, profile_image
        provider:
          naver:
            authorization-uri: https://nid.naver.com/oauth2.0/authorize
            token-uri: https://nid.naver.com/oauth2.0/token
            user-info-uri: https://openapi.naver.com/v1/nid/me
            user-name-attribute: response
```
✅ **핵심 요약:** 네이버 API를 통해 로그인할 때 필요한 정보(client-id, secret, API URL)를 설정해줘야 해요!

### ✅ **Spring Security에서 OAuth2 적용 (`SecurityConfig.java`)**
```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf().disable()
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/", "/login").permitAll()
            .anyRequest().authenticated()
        )
        .oauth2Login()
        .userInfoEndpoint()
        .userService(customOAuth2UserService());
    return http.build();
}

@Bean
public OAuth2UserService<OAuth2UserRequest, OAuth2User> customOAuth2UserService() {
    return new CustomOAuth2UserService();
}
```
✅ **핵심 요약:** Spring Security의 OAuth2 기능을 활성화하고, 네이버 로그인을 처리하는 `CustomOAuth2UserService`를 추가했어요!

### ✅ **네이버 사용자 정보 조회 (`CustomOAuth2UserService.java`)**
```java
@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        return new DefaultOAuth2User(Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")),
                                     oAuth2User.getAttributes(), "response");
    }
}
```
✅ **핵심 요약:** 네이버에서 제공하는 사용자 정보를 받아와서 Spring Security에서 사용할 수 있도록 변환해요!

---

## 🎯 **마무리 정리 (한눈에 요약!)**
| 기능 | 핵심 개념 |
|------|---------|
| **Spring Security 로그인** | ID & 비밀번호를 검증하는 기본 로그인 방식 |
| **OAuth2 네이버 로그인** | 네이버 API를 사용하여 로그인 처리 (Authorization Code → Access Token → 사용자 정보) |
| **Security 설정** | `/login`, `/register`는 인증 없이 접근 가능, 나머지는 로그인 필요 |
| **OAuth2 설정** | `application.yml`에서 네이버 API 설정 후, SecurityConfig에서 적용 |

🎉 **이제 Spring Security와 네이버 로그인 구현 방법을 알았어요!**

이 문서를 GitHub README에 올리면, 처음 배우는 사람도 쉽게 이해할 수 있을 거예요! 🚀🔥


