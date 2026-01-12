package com.example.httpclient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class HttpClientDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(HttpClientDemoApplication.class, args);
    }
}