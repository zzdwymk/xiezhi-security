package com.bachelor.toolbox.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
  private final JwtService jwtService;
  private final UserRepository users;

  public JwtAuthenticationFilter(JwtService jwtService, UserRepository users) {
    this.jwtService = jwtService;
    this.users = users;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String header = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (header != null && header.startsWith("Bearer "))
      try {
        Claims claims = jwtService.parse(header.substring(7));
        String username = claims.getSubject();
        long tokenVersion = tokenVersion(claims);
        users
            .findByUsername(username)
            .filter(User::isEnabled)
            .filter(user -> tokenVersion == currentTokenVersion(user))
            .ifPresent(
                user ->
                    SecurityContextHolder.getContext()
                        .setAuthentication(
                            new UsernamePasswordAuthenticationToken(
                                user,
                                null,
                                List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole())))));
      } catch (JwtException | IllegalArgumentException ignored) {
        SecurityContextHolder.clearContext();
      }
    chain.doFilter(request, response);
  }

  /** 旧版本签发的令牌没有 ver 声明，按版本 0 处理以保持升级兼容。 */
  private static long tokenVersion(Claims claims) {
    Object value = claims.get("ver");
    return value instanceof Number number ? number.longValue() : 0L;
  }

  private static long currentTokenVersion(User user) {
    return user.getTokenVersion() == null ? 0L : user.getTokenVersion();
  }
}
