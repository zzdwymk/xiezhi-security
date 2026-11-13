package com.bachelor.toolbox.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

/** 修改密码的最小长度与默认口令防呆——Round 26。 */
@DisplayName("修改密码策略（Round 26）")
class AuthControllerChangePasswordTests {
  private final UserRepository users = mock(UserRepository.class);
  private final PasswordEncoder encoder = mock(PasswordEncoder.class);
  private final AuthController controller =
      new AuthController(users, encoder, mock(JwtService.class), mock(LoginAttemptService.class),
          mock(AuditService.class));

  private User user() {
    User u = new User();
    u.setUsername("admin");
    u.setPasswordHash("HASH");
    u.setEnabled(true);
    when(users.findByUsername("admin")).thenReturn(Optional.of(u));
    when(encoder.matches("cur", "HASH")).thenReturn(true);
    return u;
  }

  @Test
  @DisplayName("CP-1 过短新密码(<8) → 拒绝")
  void rejectsShortPassword() {
    user();
    assertThatThrownBy(() -> controller.changePassword(
        principal(), new ChangePasswordRequest("cur", "short7")))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("8");
  }

  @Test
  @DisplayName("CP-2 默认开发口令 admin123 → 拒绝")
  void rejectsDefaultPassword() {
    user();
    assertThatThrownBy(() -> controller.changePassword(
        principal(), new ChangePasswordRequest("cur", "admin123")))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("默认口令");
  }

  @Test
  @DisplayName("CP-3 当前密码错误 → 拒绝")
  void rejectsWrongCurrent() {
    user();
    when(encoder.matches("bad", "HASH")).thenReturn(false);
    assertThatThrownBy(() -> controller.changePassword(
        principal(), new ChangePasswordRequest("bad", "StrongPass123")))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("当前密码");
  }

  @Test
  @DisplayName("CP-4 合法强密码 → 成功并更新")
  void acceptsStrongPassword() {
    User u = user();
    when(encoder.encode("StrongPass123")).thenReturn("NEWHASH");
    var r = controller.changePassword(principal(), new ChangePasswordRequest("cur", "StrongPass123"));
    assertThat(r).containsEntry("changed", true);
    assertThat(u.getPasswordHash()).isEqualTo("NEWHASH");
  }

  private User principal() {
    User p = new User();
    p.setUsername("admin");
    return p;
  }
}
