package com.bachelor.toolbox.auth;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.Map;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
  private final UserRepository users;
  private final PasswordEncoder encoder;
  private final JwtService jwt;
  private final LoginAttemptService loginAttempts;
  private final AuditService auditService;

  public AuthController(
      UserRepository users,
      PasswordEncoder encoder,
      JwtService jwt,
      LoginAttemptService loginAttempts,
      AuditService auditService) {
    this.users = users;
    this.encoder = encoder;
    this.jwt = jwt;
    this.loginAttempts = loginAttempts;
    this.auditService = auditService;
  }

  @PostMapping("/login")
  public AuthResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest http) {
    String clientAddress = http.getRemoteAddr();
    String username = request.username();

    if (loginAttempts.isBlocked(username, clientAddress)) {
      long remaining = loginAttempts.remainingLockSeconds(username, clientAddress);
      auditService.record("LOGIN", "USER", null, "账户暂时锁定：" + username, "BLOCKED");
      throw new ApiException("登录尝试过于频繁，请在 " + remaining + " 秒后重试");
    }

    User user =
        users
            .findByUsername(username)
            .filter(User::isEnabled)
            .filter(candidate -> encoder.matches(request.password(), candidate.getPasswordHash()))
            .orElse(null);

    if (user == null) {
      loginAttempts.recordFailure(username, clientAddress);
      auditService.record("LOGIN", "USER", null, "登录失败：" + username, "FAILED");
      // 统一错误信息，不区分“用户不存在”与“密码错误”，避免用户枚举
      throw new BadCredentialsException("用户名或密码错误");
    }

    loginAttempts.recordSuccess(username, clientAddress);
    auditService.record("LOGIN", "USER", user.getId(), "登录成功：" + username, "SUCCESS");
    return new AuthResponse(
        jwt.createToken(user), "Bearer", jwt.expirationSeconds(), AuthResponse.UserView.from(user));
  }

  @GetMapping("/me")
  public AuthResponse.UserView me(@AuthenticationPrincipal User user) {
    return AuthResponse.UserView.from(user);
  }

  @PostMapping("/change-password")
  public Map<String, Object> changePassword(
      @AuthenticationPrincipal User principal, @Valid @RequestBody ChangePasswordRequest request) {
    if (principal == null) {
      throw new BadCredentialsException("当前登录状态无效");
    }

    User user =
        users.findByUsername(principal.getUsername()).orElseThrow(() -> new ApiException("用户不存在"));
    String currentPassword = request.currentPassword();

    if (!encoder.matches(currentPassword, user.getPasswordHash())) {
      throw new ApiException("当前密码不正确");
    }
    if ("admin123".equals(request.newPassword())) {
      throw new ApiException("该口令为受限的开发默认口令，请更换后重试");
    }

    user.setPasswordHash(encoder.encode(request.newPassword()));
    users.save(user);
    return Map.of("changed", true);
  }
}
