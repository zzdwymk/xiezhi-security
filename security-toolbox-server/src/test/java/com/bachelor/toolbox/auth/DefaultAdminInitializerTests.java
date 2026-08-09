package com.bachelor.toolbox.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.traffic.MitmCertificateAuthority;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
@ExtendWith(OutputCaptureExtension.class)
class DefaultAdminInitializerTests {
  @Mock private UserRepository users;
  @Mock private PasswordEncoder encoder;
  @Mock private ApplicationArguments arguments;
  @Mock private MitmCertificateAuthority certificateAuthority;

  @Test
  void createsAdministratorWithConfiguredPassword() {
    when(users.findByUsername("admin")).thenReturn(Optional.empty());
    when(encoder.encode("generated-desktop-password")).thenReturn("encoded-password");

    initializer("generated-desktop-password", true, true).run(arguments);

    ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
    verify(users).save(saved.capture());
    assertThat(saved.getValue().getUsername()).isEqualTo("admin");
    assertThat(saved.getValue().getPasswordHash()).isEqualTo("encoded-password");
    assertThat(saved.getValue().getRole()).isEqualTo("ADMIN");
  }

  @Test
  void doesNotInitializeCertificateAuthorityOutsideLegacyMigration() {
    when(users.findByUsername("admin")).thenReturn(Optional.of(administrator("hash")));
    @SuppressWarnings("unchecked")
    ObjectProvider<MitmCertificateAuthority> provider =
        org.mockito.Mockito.mock(ObjectProvider.class);
    DefaultAdminInitializer initializer =
        new DefaultAdminInitializer(
            users,
            encoder,
            "generated-desktop-password",
            true,
            true,
            false,
            false,
            provider);

    initializer.run(arguments);

    verifyNoInteractions(provider);
  }

  @Test
  void doesNotResyncExistingAdministratorPasswordAcrossLaunches(CapturedOutput output) {
    User admin = administrator("old-password-hash");
    when(users.findByUsername("admin")).thenReturn(Optional.of(admin));

    initializer("generated-desktop-password", true, true).run(arguments);

    // The desktop admin password is user-managed: an existing admin is never overwritten on
    // launch, so a password the user sets in 系统设置 → 修改登录密码 persists across restarts.
    assertThat(admin.getPasswordHash()).isEqualTo("old-password-hash");
    verify(users, never()).save(admin);
    assertThat(output).contains("桌面端管理员凭据由用户管理，已跳过本次启动时的密码同步");
  }

  @Test
  void doesNotSynchronizeWhenDesktopModeIsDisabled() {
    User admin = administrator("old-password-hash");
    when(users.findByUsername("admin")).thenReturn(Optional.of(admin));

    initializer("generated-desktop-password", false, true).run(arguments);

    assertThat(admin.getPasswordHash()).isEqualTo("old-password-hash");
    verify(encoder, never()).matches("generated-desktop-password", "old-password-hash");
    verify(users, never()).save(admin);
  }

  @Test
  void doesNotSynchronizeWithoutExplicitDesktopSwitch() {
    User admin = administrator("old-password-hash");
    when(users.findByUsername("admin")).thenReturn(Optional.of(admin));

    initializer("generated-desktop-password", true, false).run(arguments);

    assertThat(admin.getPasswordHash()).isEqualTo("old-password-hash");
    verify(encoder, never()).matches("generated-desktop-password", "old-password-hash");
    verify(users, never()).save(admin);
  }

  @Test
  void rejectsEmptyAdministratorPassword() {
    assertThatThrownBy(() -> initializer(" ", true, true).run(arguments))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("管理员密码不能为空");
    verify(users, never()).findByUsername("admin");
  }

  @Test
  void rejectsFixedDevelopmentPasswordWithoutExplicitOptIn() {
    DefaultAdminInitializer initializer =
        new DefaultAdminInitializer(users, encoder, "admin123", false, false, false);

    assertThatThrownBy(() -> initializer.run(arguments))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("默认管理员密码已禁用，请将 ADMIN_PASSWORD 设置为高强度密码");
    verify(users, never()).findByUsername("admin");
  }

  @Test
  void allowsFixedDevelopmentPasswordOnlyWithExplicitOptIn(CapturedOutput output) {
    when(users.findByUsername("admin")).thenReturn(Optional.empty());
    when(encoder.encode("admin123")).thenReturn("development-hash");
    DefaultAdminInitializer initializer =
        new DefaultAdminInitializer(users, encoder, "admin123", false, false, true);

    initializer.run(arguments);

    verify(users)
        .save(
            org.mockito.ArgumentMatchers.argThat(
                user -> "development-hash".equals(user.getPasswordHash())));
    assertThat(output).contains("当前正在使用默认开发管理员密码，部署前请设置 ADMIN_PASSWORD");
  }

  @Test
  void migratesOnlyTheMatchingLegacyAdministratorAfterCaValidation(CapturedOutput output) {
    User admin = administrator("legacy-password-hash");
    when(users.findByUsername("admin")).thenReturn(Optional.of(admin));
    when(certificateAuthority.enabled()).thenReturn(true);
    when(certificateAuthority.usesConfiguredPassword()).thenReturn(false);
    when(certificateAuthority.usesLegacyDevelopmentPassword()).thenReturn(true);
    when(encoder.matches("generated-migration-password", "legacy-password-hash")).thenReturn(false);
    when(encoder.matches("admin123", "legacy-password-hash")).thenReturn(true);
    when(encoder.encode("generated-migration-password")).thenReturn("migrated-password-hash");

    migrationInitializer("generated-migration-password").run(arguments);

    verify(certificateAuthority).migrateLegacyDevelopmentPassword();
    verify(users).saveAndFlush(admin);
    assertThat(admin.getPasswordHash()).isEqualTo("migrated-password-hash");
    assertThat(output).contains("旧版开发凭据已迁移为受保护的生成值");
  }

  @Test
  void rejectsNonLegacyAdministratorWithoutChangingCaOrDatabase() {
    User admin = administrator("user-managed-password-hash");
    when(users.findByUsername("admin")).thenReturn(Optional.of(admin));
    when(certificateAuthority.enabled()).thenReturn(true);
    when(certificateAuthority.usesConfiguredPassword()).thenReturn(false);
    when(certificateAuthority.usesLegacyDevelopmentPassword()).thenReturn(true);
    when(encoder.matches("generated-migration-password", "user-managed-password-hash"))
        .thenReturn(false);
    when(encoder.matches("admin123", "user-managed-password-hash")).thenReturn(false);

    assertThatThrownBy(() -> migrationInitializer("generated-migration-password").run(arguments))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("现有管理员凭据不是旧版开发默认值，未执行迁移");

    verify(certificateAuthority, never()).migrateLegacyDevelopmentPassword();
    verify(users, never()).saveAndFlush(admin);
    assertThat(admin.getPasswordHash()).isEqualTo("user-managed-password-hash");
  }

  @Test
  void rejectsUnvalidatedCaWithoutChangingLegacyAdministrator() {
    User admin = administrator("legacy-password-hash");
    when(users.findByUsername("admin")).thenReturn(Optional.of(admin));
    when(certificateAuthority.enabled()).thenReturn(true);
    when(certificateAuthority.usesConfiguredPassword()).thenReturn(false);
    when(certificateAuthority.usesLegacyDevelopmentPassword()).thenReturn(false);
    when(encoder.matches("generated-migration-password", "legacy-password-hash")).thenReturn(false);
    when(encoder.matches("admin123", "legacy-password-hash")).thenReturn(true);

    assertThatThrownBy(() -> migrationInitializer("generated-migration-password").run(arguments))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("现有 HTTPS 中间人证书颁发机构未使用旧版或当前配置密码，未执行迁移");

    verify(users, never()).saveAndFlush(admin);
    assertThat(admin.getPasswordHash()).isEqualTo("legacy-password-hash");
  }

  @Test
  void retriesAfterCaWasMigratedButAdministratorWasNot() {
    User admin = administrator("legacy-password-hash");
    when(users.findByUsername("admin")).thenReturn(Optional.of(admin));
    when(certificateAuthority.enabled()).thenReturn(true);
    when(certificateAuthority.usesConfiguredPassword()).thenReturn(true);
    when(certificateAuthority.usesLegacyDevelopmentPassword()).thenReturn(false);
    when(encoder.matches("generated-migration-password", "legacy-password-hash")).thenReturn(false);
    when(encoder.matches("admin123", "legacy-password-hash")).thenReturn(true);
    when(encoder.encode("generated-migration-password")).thenReturn("migrated-password-hash");

    migrationInitializer("generated-migration-password").run(arguments);

    verify(certificateAuthority, never()).migrateLegacyDevelopmentPassword();
    verify(users).saveAndFlush(admin);
    assertThat(admin.getPasswordHash()).isEqualTo("migrated-password-hash");
  }

  @Test
  void retriesAfterAdministratorWasMigratedButCaWasNot() {
    User admin = administrator("migrated-password-hash");
    when(users.findByUsername("admin")).thenReturn(Optional.of(admin));
    when(certificateAuthority.enabled()).thenReturn(true);
    when(certificateAuthority.usesConfiguredPassword()).thenReturn(false);
    when(certificateAuthority.usesLegacyDevelopmentPassword()).thenReturn(true);
    when(encoder.matches("generated-migration-password", "migrated-password-hash"))
        .thenReturn(true);

    migrationInitializer("generated-migration-password").run(arguments);

    verify(certificateAuthority).migrateLegacyDevelopmentPassword();
    verify(users, never()).saveAndFlush(admin);
    assertThat(admin.getPasswordHash()).isEqualTo("migrated-password-hash");
  }

  @Test
  void rejectsShortPasswordForLegacyMigration() {
    when(users.findByUsername("admin")).thenReturn(Optional.empty());

    assertThatThrownBy(() -> migrationInitializer("short-password").run(arguments))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("迁移旧版管理员凭据时，新密码长度不得少于 16 个字符");
  }

  @Test
  void rejectsLegacyMigrationWithoutExistingAdministrator() {
    when(users.findByUsername("admin")).thenReturn(Optional.empty());

    assertThatThrownBy(() -> migrationInitializer("generated-migration-password").run(arguments))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("迁移旧版开发凭据需要现有的管理员账户");
  }

  @Test
  void rejectsLegacyMigrationWithoutEnabledCertificateAuthority() {
    User admin = administrator("legacy-password-hash");
    when(users.findByUsername("admin")).thenReturn(Optional.of(admin));
    when(certificateAuthority.enabled()).thenReturn(false);

    assertThatThrownBy(() -> migrationInitializer("generated-migration-password").run(arguments))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("迁移旧版开发凭据需要现有的 HTTPS 中间人（MITM）证书颁发机构");
  }

  private DefaultAdminInitializer initializer(
      String password, boolean desktopMode, boolean synchronize) {
    return new DefaultAdminInitializer(users, encoder, password, desktopMode, synchronize, false);
  }

  private DefaultAdminInitializer migrationInitializer(String password) {
    return new DefaultAdminInitializer(
        users, encoder, password, false, false, false, true, certificateAuthority);
  }

  private static User administrator(String hash) {
    User admin = new User();
    admin.setUsername("admin");
    admin.setPasswordHash(hash);
    admin.setRole("ADMIN");
    return admin;
  }
}
