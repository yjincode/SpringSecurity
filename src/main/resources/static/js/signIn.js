$(document).ready(() => {
    if(checkToken()){
        alert("유효하지 않은 접근방식 입니다");
        window.location.href = '/'
    }

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

});
