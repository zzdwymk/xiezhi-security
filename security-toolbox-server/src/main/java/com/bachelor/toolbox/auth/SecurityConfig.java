package com.bachelor.toolbox.auth;

import com.bachelor.toolbox.common.ApiErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {
  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  UserDetailsService userDetailsService(UserRepository users) {
    return username ->
        users
            .findByUsername(username)
            .map(
                user ->
                    org.springframework.security.core.userdetails.User.withUsername(
                            user.getUsername())
                        .password(user.getPasswordHash())
                        .roles(user.getRole())
                        .disabled(!user.isEnabled())
                        .build())
            .orElseThrow(() -> new UsernameNotFoundException("用户不存在"));
  }

  @Bean
  SecurityFilterChain securityFilterChain(
      HttpSecurity http, JwtAuthenticationFilter filter, ObjectMapper objectMapper)
      throws Exception {
    return http.csrf(csrf -> csrf.disable())
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(
            authorize ->
                authorize
                    .dispatcherTypeMatchers(DispatcherType.ASYNC, DispatcherType.ERROR)
                    .permitAll()
                    .requestMatchers(
                        "/api/auth/login",
                        "/api/system/health",
                        "/api/system/dependencies",
                        "/api/system/shutdown",
                        "/error")
                    .permitAll()
                    .requestMatchers(HttpMethod.POST, "/api/active-scans")
                    .hasRole("ADMIN")
                    .requestMatchers(HttpMethod.POST, "/api/vulnerabilities/sync/**")
                    .hasRole("ADMIN")
                    .requestMatchers(HttpMethod.PUT, "/api/fingerprints/catalog")
                    .hasRole("ADMIN")
                    .requestMatchers(HttpMethod.POST, "/api/fingerprints/catalog/reload")
                    .hasRole("ADMIN")
                    .requestMatchers(HttpMethod.DELETE, "/api/vulnerabilities/catalog")
                    .hasRole("ADMIN")
                    .requestMatchers(HttpMethod.POST, "/api/post-scan-paths/*/confirm")
                    .hasRole("ADMIN")
                    .requestMatchers(HttpMethod.POST, "/api/regression/**")
                    .hasRole("ADMIN")
                    .requestMatchers(HttpMethod.GET, "/api/regression/**")
                    .hasRole("ADMIN")
                    .requestMatchers(HttpMethod.POST, "/api/tasks/*/cancel", "/api/tasks/*/retry")
                    .authenticated()
                    .requestMatchers(HttpMethod.POST, "/api/projects/*/approvals/*/decision")
                    .hasRole("ADMIN")
                    .requestMatchers(
                        HttpMethod.POST,
                        "/api/ai/agent",
                        "/api/ai/agent/stream",
                        "/api/ai/dispatches",
                        "/api/ai/dispatches/stream")
                    .hasRole("ADMIN")
                    .requestMatchers(HttpMethod.PUT, "/api/ai/workflow")
                    .hasRole("ADMIN")
                    .requestMatchers(HttpMethod.DELETE, "/api/ai/agent/sessions/*")
                    .hasRole("ADMIN")
                    .requestMatchers(HttpMethod.DELETE, "/api/settings/data")
                    .hasRole("ADMIN")
                    .requestMatchers(HttpMethod.GET, "/api/reports/projects/**")
                    .hasRole("ADMIN")
                    .requestMatchers(HttpMethod.POST, "/api/scan-schedules/**")
                    .hasRole("ADMIN")
                    .requestMatchers(HttpMethod.PUT, "/api/scan-schedules/**")
                    .hasRole("ADMIN")
                    .requestMatchers(HttpMethod.DELETE, "/api/scan-schedules/**")
                    .hasRole("ADMIN")
                    .requestMatchers(HttpMethod.POST, "/api/traffic/**")
                    .hasRole("ADMIN")
                    .requestMatchers(HttpMethod.DELETE, "/api/traffic/**")
                    .hasRole("ADMIN")
                    .requestMatchers(HttpMethod.POST, "/api/projects/*/security-actions/**")
                    .hasRole("ADMIN")
                    .requestMatchers("/api/**")
                    .authenticated()
                    .anyRequest()
                    .permitAll())
        .exceptionHandling(
            exceptions ->
                exceptions.authenticationEntryPoint(
                    (request, response, exception) -> {
                      response.setStatus(HttpStatus.UNAUTHORIZED.value());
                      response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                      objectMapper.writeValue(
                          response.getOutputStream(),
                          ApiErrorResponse.of(HttpStatus.UNAUTHORIZED.value(), "请先登录后再继续操作"));
                    }))
        .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
        .build();
  }
}
