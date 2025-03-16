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

2. **소프트웨어 보안이란?**

현재의 소프트웨어는 상당부분이 민감한 정보일 수 있는 대량의 데이터를 관리한다.

유출됐을 때 위험성이 높은 정보는(예를들면 신용 카드 정보, 사용자의 주소, 비밀번호 등등)

더욱 중요하게 보안을 고려해야 한다. 애플리케이션은 이러한 정보에 접근, 변경 또는

가로챌 기회가 없게해야 하며 의도된 사용자가 이외의 대상은 어떤 식으로든 데이터와 상호작용

할 수 없게 해야한다 이것이 광범위하게 표현한 보안의 의미다.

*보안은 뚫릴 수 밖에 없다 그러니 보안을 생각할 때는 악성사용자가 보안을 뚫고 들어왔을때를*

*염두해 두고 어떤식으로 대처하고 데이터를 지킬 것인가 에 대한 고민을 해야한다*

<br/><br/><br/><br/>


# Spring Security 구조 & OAuth2 활용한 네이버 아이디 로그인
💡

### **Spring Security의 주요 컴포넌트**

Spring Security의 인증(Authentication)과 인가(Authorization)는 다음과 같은 주요 컴포넌트로 이루어져 있다

| 컴포넌트 | 역할 |
| --- | --- |
| `SecurityFilterChain` | 요청을 가로채고 여러 필터를 실행하는 보안 필터 체인 |
| `UsernamePasswordAuthenticationFilter` | 로그인 요청을 처리하는 필터 |
| `AuthenticationManager` | 인증 요청을 위임하는 관리자 |
| `UserDetailsService` | DB에서 사용자 정보를 조회하는 서비스 |
| `PasswordEncoder` | 비밀번호 암호화 및 비교 |
| `SecurityContextHolder` | 인증 정보를 저장하는 컨텍스트 |

<br/><br/>
### Spring Security 로그인 과정
- 우선 Spring Security에서 가장 기본적인 **폼 로그인 (Form Login)** 방식
    1. 사용자가 ID, PW 입력 후 로그인 버튼 클릭 (POST /login 요청)
    2. Spring Security가 로그인 요청을 가로챔 (UsernamePasswordAuthenticationFilter)
    3. 입력된 ID & PW를 DB에서 조회 (UserDetailsService)
    4. 비밀번호 일치 여부 확인 (PasswordEncoder)
    5. 인증 성공하면 사용자 정보를 저장 (SecurityContextHolder)
    6. 로그인 성공 후 세션 기반 인증 (Session Cookie 발급) → 이후 요청에서 인증 정보를 활용
위 방식은 기본적으로 세션을 이용하는 방식이며, 브라우저가 세션 쿠키를 저장하여 인증을 유지한다

<br/><br/>

**하지만 FormLogin 방식에는 단점이 많았다 주요 단점으로는**

- 서버의 세션 관리 부담
    - 사용자가 많아지면 서버가 많은 세션을 관리해야 하므로 메모리 사용량이 증가.
- CSRF(Cross-Site Request Forgery) 공격에 취약
    - 세션 쿠키를 이용하는 방식이기 때문에 악의적인 요청이 사용자의 세션을 탈취할 가능성이 있음.
- 모바일 앱과의 연동 어려움
    - 세션 기반 인증은 브라우저 중심으로 설계됨.
- 서버가 상태를 유지해야 함
    - 서버가 다운되거나 재시작되면 로그인 세션도 사라지는 문제가 있음.

<br/><br/>

이러한 취약점들을 보완 한것이 JWT 기반 로그인 방식이다
- 서버의 세션 관리 부담 → 브라우저에서 AccessToken 을 직접 관리
- CSRF 공격에 취약 →  요청마다 Authorization 헤더를 사용하고, 쿠키 기반 인증을 사용하지 않음
- 모바일 앱과의 연동 어려움 → 모바일, 웹 에서 동일한 방식으로 인증 가능
- 서버가 상태를 유지해야 함 → 서버는 JWT만 검증하고, 따로 인증을 저장하지 않음 (무상태 인증)

<br/><br/>
### **JWT를 활용한 로그인 과정**

- JWT 활용한 회원 인증 과정
    1. 사용자가 ID, PW 입력 후 로그인 버튼 클릭 (POST /login 요청)
    2. Spring Security가 로그인 요청을 가로챔 
    3. 입력된 ID & PW를 DB에서 조회 ( UserDetailsService )
    4. 비밀번호 일치 여부 확인 ( BCryptPasswordEncoder )
    5. 인증 성공하면 JWT AccessToken, RefreshToken을 생성하여 응답
    6. 이후 사용자는 API 요청 시 AccessToken을 헤더에 포함하여 요청
    7. 서버에서는 ( TokenApiService ) 를 통해 AccessToken 검증
    8. 인증이 유효하면 요청을 정상 처리, 만료되면 RefreshToken을 이용해 새 AccessToken 발급
<br/><br/>
위의 과정을 이번에 만들어본 코드와 비교하면 아래와 같다
<br/><br/>
1. 사용자가 ID, PW 입력 후 로그인 버튼 클릭 (POST /login 요청)
    
    ```jsx
    $('#signin').click(() => {
            let userId = $('#user_id').val();
            let password = $('#password').val();
    
            let formData = {
                userId : userId,
                password : password
            }
    
            $.ajax({
                type: 'POST',
                url: '/login',
                data: JSON.stringify(formData), // 데이터를 JSON 형식으로 변환
                contentType: 'application/json; charset=utf-8', // 전송 데이터의 타입
                dataType: 'json', // 서버에서 받을 데이터의 타입
                success: (response) => {
                    if(response.success){
                        alert('로그인이 성공했습니다.');
                        console.log(response);
                        localStorage.setItem('accessToken', response.token);
                        window.location.href = '/'
                    } else {
                        alert('아이디/비밀번호가 일치하지 않습니다.')
                    }
                },
                error: (error) => {
                    console.log('오류발생 : ', error);
                    alert('로그인 중 오류가 발생했습니다.');
                }
            });
    
        });
    ```
    

2. Spring Security가 로그인 요청을 가로챔 
    
    ```java
      // form로그인 방식이아닌 jwt 인증을 먼저 수행하기 위해
      // WebSecurityConfig 에서 
      // UsernamePasswordAuthenticationFilter 보다 
      // tokenAuthenticationFilter 가 먼저 동작하도록 설정 
      
       .addFilterBefore(tokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
    ```
    
3. 입력된 ID & PW를 DB에서 조회 (UserDetailsService)
    
    ```java
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
    ```
    
4. 비밀번호 일치 여부 확인 ( BCryptPasswordEncoder )
    
    ```java
    @Getter
    public class SignUpRequestDTO {
        private String userId;
        private String userName;
        private String password;
    
        public Member toMember(BCryptPasswordEncoder bCryptPasswordEncoder) {
            return Member.builder()
                    .userId(userId)
                    .password(bCryptPasswordEncoder.encode(password))
                    .userName(userName)
                    .build();
        }
    }
    ```
    
    ```java
    // WebSecurityConfig 에서 빈 주입
     @Bean
        public BCryptPasswordEncoder bCryptPasswordEncoder() {
            return new BCryptPasswordEncoder();
        }
    ```
    
5. 인증 성공하면 JWT AccessToken, RefreshToken을 생성하여 응답
    
    ```java
    // MemberApiController
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
            }catch (BadCredentialsException e) { // 아이디 비밀번호 불일치시 반환값
                return SignInResponseDTO.builder()
                        .success(false)
                        .build();
            }
    }
    ```
    
6. 이후 사용자는 API 요청 시 AccessToken을 헤더에 포함하여 요청
    
    ```jsx
    let setupAjax = () => {
        // 모든 Ajax 요청에 JWT Access Token을 포함.
        $.ajaxSetup({
            beforeSend: (xhr) => {
                let token = localStorage.getItem('accessToken');
                if (token) {
                    xhr.setRequestHeader('Authorization', 'Bearer ' + token)
                }
            }
        })
    }
    
    // Ajax 요청시 브라우저의 로컬스토리지에서 가져온 엑세스토큰을 헤더에 포함시켜 보낸다
    ```
    
7. 서버에서는( TokenApiService) 를 통해 AccessToken 검증
8. 인증이 유효하면 요청을 정상 처리, 만료되면 RefreshToken을 이용해 새 AccessToken 발급
    
    ```jsx
    @Service
    @RequiredArgsConstructor
    public class TokenApiService {
    
        private final TokenProvider tokenProvider;
    
        public ResponseEntity<?> refreshAccessToken(HttpServletRequest request, HttpServletResponse response) {
            String refreshToken = CookieUtil.getCookieValue(request, "refreshToken");
    
            if (refreshToken == null || tokenProvider.validToken(refreshToken) != 1) {
                return ResponseEntity
                        .status(HttpStatus.UNAUTHORIZED)
                        .body("Refresh Token이 유효하지 않습니다.");
            }
    
            Member member = tokenProvider.getTokenDetails(refreshToken);
    
            String newAccessToken = tokenProvider.generateToken(member, Duration.ofHours(2));
            String newRefreshToken = tokenProvider.generateToken(member, Duration.ofDays(2));
    
            CookieUtil.addCookie(response, "refreshToken", newRefreshToken, 7 * 24 * 60 * 60);
    
            response.setHeader(HttpHeaders.AUTHORIZATION, newAccessToken);
    
            return ResponseEntity.ok(
                    SignInResponseDTO.builder()
                            .token(newAccessToken)
                            .build()
            );
        }
    }
    ```
    

---

##

## OAuth2 를 이용한 네이버아이디 로그인

### **OAuth2 로그인 과정**

1. 사용자가 **네이버 로그인 버튼 클릭** → 네이버 로그인 페이지로 이동
2. 네이버에서 로그인 시 Authorization Code를 받아 **네이버 서버에 Access Token 요청**
3. 네이버가 **Access Token 발급** → Spring Boot가 사용자 정보 요청
4. 사용자 정보를 DB를 조회하여 미중복시 DB에 저장
5. 서버에서 기존과 동일한 방법으로 토큰 생성
6. 저장된 토큰으로 기존의 JWT 인증 방식으로 로그인

코드 구성은 다음과 같다

### **네이버 로그인 설정 (yml 설정)**

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          naver:
            client-id: 네이버에서 제공한 client-id
            client-secret: 네이버에서 제공한 client-secret
            client-name: Naver
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/login/oauth2/code/naver"
            scope:
              - name
        provider:
          naver:
            authorization-uri: https://nid.naver.com/oauth2.0/authorize
            token-uri: https://nid.naver.com/oauth2.0/token
            user-info-uri: https://openapi.naver.com/v1/nid/me
            user-name-attribute: response

```

### WebSecurityConfig에 Bean주입

```java
	@Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                ...중략...
    .oauth2Login(oauth2 -> oauth2
			      .loginPage("/login")  // 로그인 페이지 URL 지정
		        .successHandler(successHandler)  //성공시           
		        .failureHandler((request, response, exception) -> {
                   response.sendRedirect("/login");  // 로그인 실패 시 리디렉트
                        })
                )
```

1. 사용자가 **네이버 로그인 버튼 클릭** → 네이버 로그인 페이지로 이동
    
    ```jsx
    $('#naver-signin').click(() => {
            window.location.href = "/oauth2/authorization/naver"
    ...생략
    ```
    
2. 네이버에서 로그인 후 **Authorization Code 발급**
3. 네이버가 **Access Token 발급** → Spring Boot가 사용자 정보 요청
4. 사용자 정보를 DB를 조회하여 미중복시 DB에 저장
5. 서버에서 기존과 동일한 방법으로 토큰 생성
    
    ```jsx
    $('#naver-signin').click(() => {
            window.location.href = "/oauth2/authorization/naver"
    
                $.ajax({
                    url: "/auth/user",
                    type: "GET",
                    dataType: "json",
                    success: (response) => {
                        if (response.success) {
                            localStorage.setItem("accessToken", response.token);
                            console.log("JWT 저장 완료:", response.token);
    
                                window.location.href = "/";
    
                        } else {
                            alert("로그인 실패! 다시 시도하세요.");
                            window.location.href = "/login";
                        }
                    },
                    error: (xhr, status, error) => {
                        console.error("로그인 정보 요청 오류:", error);
                        alert("로그인 중 오류가 발생했습니다.");
                        window.location.href = "/login";
                    }
                });
        });
    ```
    
    발급받은 유저 정보가 담긴 Code 는 CustomOAuth2UserService 에서 처리된다
    
    ```jsx
    
    @RequiredArgsConstructor
    public class CustomOAuth2User implements OAuth2User {
    
        private final Member member;
        private final String jwtToken;
        private final String refreshToken;
    ...생략
    ```
    
    ```jsx
    @RestController
    @RequestMapping("/auth")
    public class SocialUserApiController {
    
        @GetMapping("/user")
        public ResponseEntity<?> getUserInfo(@AuthenticationPrincipal CustomOAuth2User customOAuth2User) {
            if (customOAuth2User == null) {
                return ResponseEntity.status(401).body(Map.of("success", false, "message", "Unauthorized"));
            }
    
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "token", customOAuth2User.getJwtToken(),
                    "user", customOAuth2User.getAttributes()
            ));
        }
    ```
    
    ```jsx
    @Service
    @RequiredArgsConstructor
    public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    
        private final MemberMapper memberMapper;
        private final TokenProvider tokenProvider;
    
        @Override
        public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
            OAuth2User oAuth2User = super.loadUser(userRequest);
    
            Map<String, Object> response = (Map<String, Object>) oAuth2User.getAttributes().get("response");
            String userId = (String) response.get("id");
            String name = (String) response.get("name");
    
            Member existingMember = memberMapper.findByUserIdAndProvider(userId, Provider.naver.name());
    
            if (existingMember == null) {
                Member newMember = Member.builder()
                        .userId(userId)  // 네이버에서 받은 고유 ID 저장
                        .userName(name)  // 네이버에서 가져온 유저 이름
                        .oauthProvider(Provider.naver)
                        .build();
    
                memberMapper.insertOAuthMember(newMember);
                existingMember = newMember;  // 이후 처리 위해 변수 업데이트
            }
            String accessToken = tokenProvider.generateToken(existingMember,  Duration.ofHours(2));
            String refreshToken = tokenProvider.generateToken(existingMember, Duration.ofDays(2));
    
            return new CustomOAuth2User(existingMember, accessToken, refreshToken);
        }
    
    }
    ```
