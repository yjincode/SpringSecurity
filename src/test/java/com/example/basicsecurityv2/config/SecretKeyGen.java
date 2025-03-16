package com.example.basicsecurityv2.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@SpringBootTest
class SecretKeyGen {

    @Test
    void HS512_생성() {
        Mac sha512_HMAC = null;
        String data = "Spring boot basic board 2";
        String secretKey = "256-bit-256bit-secretkey"; // 비밀키를 적절히 설정하세요.
        try {
            sha512_HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes("UTF-8"), "HmacSHA512");
            sha512_HMAC.init(keySpec);
            byte[] macData = sha512_HMAC.doFinal(data.getBytes("UTF-8"));
            String secret_key = Base64.getEncoder().encodeToString(macData);

            System.out.println(secret_key);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

}
