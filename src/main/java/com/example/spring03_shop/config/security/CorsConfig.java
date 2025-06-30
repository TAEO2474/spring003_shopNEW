package com.example.spring03_shop.config.security;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

//스프링 설정 
@Configuration
public class CorsConfig {
	
	@Bean("customCorsSource")
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowCredentials(true);
		//config.setAllowedOrigins(List.of("http://localhost:3000","http://127.0.0.1:3001")); //프론트엔드 주소
		config.setAllowedOrigins(List.of("*"));
		config.setAllowedMethods(List.of("GET","POST","PUT","DELETE", "OPTIONS"));
		config.setAllowedHeaders(List.of("*"));
		
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", config);  //모든 경로에 대해 적용		
		return source;
	}
} //end class

/////////////////////////////////////////////////////////////

//@Configuration  //스프링 설정 클래스임을 나타냄
//public class CorsConfig {
//
////@Bean CorsFilter:	CORS 처리를 위한 필터를 스프링 빈으로 등록
//// CorsFilter:	모든 HTTP 요청에 대해 CORS 정책을 적용
//@Bean  
//public CorsFilter corsFilter() {      
//CorsConfiguration config = new CorsConfiguration();
//config.setAllowCredentials(true);
//config.setAllowedOrigins(List.of("http://localhost:3000","http://127.0.0.1:3000")); // 프론트엔드 주소
//config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
//config.setAllowedHeaders(List.of("*"));
//
//UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//source.registerCorsConfiguration("/api/**", config);
//return new CorsFilter(source);
//}
//}


//CorsConfig보다 CorsConfigurationSource를 @Bean으로 등록하는 쪽이 Spring Security 6에서 가장 깔끔하고 호환성 높은 방식이다
/////////////////////////////////////////////////////










