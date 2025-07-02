package com.example.spring03_shop.config.jwt;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.spring03_shop.members.dto.AuthInfo;
import org.springframework.stereotype.Component;
import java.util.Date;

@Component
public class JwtTokenProvider {
   private final String secretKey = "mySecurityCos";
   // (1) accessToken: 1분 유효 (보통 1~2시간으로 설정, 해킹 보호/보안를 위해서 토근을 짧게 주는거임)
   public String createAccessToken( AuthInfo authInfo ) {
       return JWT.create()
               .withSubject("AccessToken")
               .withExpiresAt(new Date(System.currentTimeMillis() + 1000 * 60 )) //1분
               .withClaim("memberEmail", authInfo.getMemberEmail())
               .withClaim("authRole", authInfo.getAuthRole().toString())
               .sign(Algorithm.HMAC512(secretKey));
   }
   // (2) refreshToken: 2주 유효 ( 리프레시 토큰의 "원본"은 서버(DB)에 저장되고, 그 "사본"은 클라이언트에 저장됩니다.)
   public String createRefreshToken(String email) {
       return JWT.create()
               .withSubject("RefreshToken")
               .withExpiresAt(new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 14)) //2주
               .withClaim("memberEmail", email)
               .sign(Algorithm.HMAC512(secretKey));
   }
   public String getEmailFromToken(String token) {
       return JWT.require(Algorithm.HMAC512(secretKey))
               .build()
               .verify(token)
               .getClaim("memberEmail")
               .asString();
   }
}





