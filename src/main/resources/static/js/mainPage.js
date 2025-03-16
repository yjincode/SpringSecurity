$(document).ready(()=>{
    if(!checkToken()){
        alert("로그인 후 이용해주세요");
        window.location.href = "/member/login"
    }
    setupAjax()
    getUserInfo().then((userinfo)=>{
        $('#userName').text(userinfo.userName).append(" 님 환영합니다")
    })

    $('#logout').click(()=>{
        localStorage.removeItem("accessToken");

        $.ajax({
            type: "POST",
            url: "/logout",
            success: () =>{
                alert("로그아웃되었습니다.");
                window.location.href = "/member/login";
            },
            error: () => {
                alert("로그아웃 실패");
            }
        });
    })
})
