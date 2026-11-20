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

    // Round 223：先原子认领尝试名额，再查库/比对密码。否则并发请求会全部在失败被记录前
    // 通过 isBlocked 检查，把失败阈值放大到并发数（实测 120 并发可放行 114 次密码校验）。
    if (!loginAttempts.beginAttempt(username, clientAddress)) {
      long remaining = loginAttempts.remainingLockSeconds(username, clientAddress);
      auditService.record("LOGIN", "USER", null, "登录尝试被限流：" + username, "BLOCKED");
      if (remaining > 0) {
        throw new ApiException("登录尝试过于频繁，请在 " + remaining + " 秒后重试");
      }
      throw new ApiException("登录尝试过于频繁，请稍后重试");
    }

    boolean attemptCompleted = false;
    try {
      User user =
          users
              .findByUsername(username)
              .filter(User::isEnabled)
              .filter(candidate -> encoder.matches(request.password(), candidate.getPasswordHash()))
              .orElse(null);

      if (user == null) {
        loginAttempts.recordFailure(username, clientAddress);
        attemptCompleted = true;
        auditService.record("LOGIN", "USER", null, "登录失败：" + username, "FAILED");
        // 统一错误信息，不区分“用户不存在”与“密码错误”，避免用户枚举
        throw new BadCredentialsException("用户名或密码错误");
      }

      loginAttempts.recordSuccess(username, clientAddress);
      attemptCompleted = true;
      auditService.record("LOGIN", "USER", user.getId(), "登录成功：" + username, "SUCCESS");
      return new AuthResponse(
          jwt.createToken(user), "Bearer", jwt.expirationSeconds(), AuthResponse.UserView.from(user));
    } finally {
      // 数据库异常等非凭据失败路径必须归还名额，避免一次故障永久占用节流额度。
      if (!attemptCompleted) {
        loginAttempts.cancelAttempt(username, clientAddress);
      }
    }
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
    // Round 26：拒绝过短新口令（降低弱口令风险；登录端点可被本机暴力/撞库，弱口令会放大风险）。
    String newPassword = request.newPassword();
    if (newPassword == null || newPassword.length() < 8) {
      throw new ApiException("新密码长度不得少于 8 个字符");
    }
    if ("admin123".equals(newPassword)) {
      throw new ApiException("该口令为受限的开发默认口令，请更换后重试");
    }

    user.setPasswordHash(encoder.encode(newPassword));
    users.save(user);
    return Map.of("changed", true);
  }
}
