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

<aside>
💡

### **Spring Security Architecture** ( 스프링 시큐리티의 구조 )


</aside>
![Image](https://private-user-images.githubusercontent.com/195647486/423197239-762deaff-1d04-446f-b6c1-1e76b3194397.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NDIxMTQxOTQsIm5iZiI6MTc0MjExMzg5NCwicGF0aCI6Ii8xOTU2NDc0ODYvNDIzMTk3MjM5LTc2MmRlYWZmLTFkMDQtNDQ2Zi1iNmMxLTFlNzZiMzE5NDM5Ny5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwMzE2JTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDMxNlQwODMxMzRaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT04YjNjZDFhMjAxMGIwZTM0OTBiOWUyMDY3MTg0MzBlYTE0ZDZlMTg3ZWMwODkxMzA0MDI1ZDdjZTQ5NjNkYmU4JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.noay46NNaD6Hg3Iy37CydXOV6SrpLt2Wm5MFMOjnmuI)
