package com.bachelor.toolbox.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

class JwtAuthenticationFilterTests {
  private final JwtService jwt = mock(JwtService.class);
  private final UserRepository users = mock(UserRepository.class);
  private final JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwt, users);

  @AfterEach void clear() { SecurityContextHolder.clearContext(); }

  private MockHttpServletRequest request() {
    var request = new MockHttpServletRequest();
    request.addHeader("Authorization", "Bearer test-token");
    return request;
  }

  @Test void invalidTokenDoesNotAuthenticate() throws Exception {
    when(jwt.parse("test-token")).thenThrow(new JwtException("invalid"));
    filter.doFilter(request(), new MockHttpServletResponse(), (req, res) ->
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull());
  }

  @Test void disabledUserDoesNotAuthenticate() throws Exception {
    Claims claims = mock(Claims.class);
    when(claims.getSubject()).thenReturn("disabled");
    when(jwt.parse("test-token")).thenReturn(claims);
    User user = new User(); user.setUsername("disabled"); user.setEnabled(false);
    when(users.findByUsername("disabled")).thenReturn(Optional.of(user));
    filter.doFilter(request(), new MockHttpServletResponse(), (req, res) ->
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull());
  }

  @Test void authoritiesFollowCurrentDatabaseRoleNotTokenClaim() throws Exception {
    Claims claims = mock(Claims.class);
    when(claims.getSubject()).thenReturn("member");
    when(claims.get("role")).thenReturn("ADMIN");
    when(jwt.parse("test-token")).thenReturn(claims);
    User user = new User(); user.setUsername("member"); user.setEnabled(true); user.setRole("USER");
    when(users.findByUsername("member")).thenReturn(Optional.of(user));
    filter.doFilter(request(), new MockHttpServletResponse(), (req, res) ->
        assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities())
            .extracting("authority").containsExactly("ROLE_USER"));
  }
}
