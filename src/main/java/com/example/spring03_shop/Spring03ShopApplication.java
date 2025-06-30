package com.example.spring03_shop;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

//@SpringBootApplication(exclude= SecurityAutoConfiguration.class)
@SpringBootApplication
public class Spring03ShopApplication {

	public static void main(String[] args) {
		SpringApplication.run(Spring03ShopApplication.class, args);
	}

}
