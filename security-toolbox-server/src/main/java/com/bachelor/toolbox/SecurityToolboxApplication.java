package com.bachelor.toolbox;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableAsync
@EnableScheduling
@SpringBootApplication
public class SecurityToolboxApplication {
  public static void main(String[] args) {
    SpringApplication.run(SecurityToolboxApplication.class, args);
  }
}
