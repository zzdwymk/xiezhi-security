package com.bachelor.toolbox.auth;

import com.bachelor.toolbox.traffic.MitmCertificateAuthority;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class DefaultAdminInitializer implements ApplicationRunner {
  private static final Logger log = LoggerFactory.getLogger(DefaultAdminInitializer.class);
  private static final String LEGACY_DEVELOPMENT_PASSWORD = "admin123";

  private final UserRepository users;
  private final PasswordEncoder encoder;
  private final String password;
  private final boolean desktopMode;
  private final boolean synchronizeDesktopPassword;
  private final boolean allowInsecureDevelopmentCredentials;
  private final boolean migrateLegacyDevelopmentCredentials;
  private final Supplier<MitmCertificateAuthority> certificateAuthority;

  @Autowired
  public DefaultAdminInitializer(
      UserRepository users,
      PasswordEncoder encoder,
      @Value("${toolbox.auth.admin-password}") String password,
      @Value("${toolbox.auth.desktop-mode:false}") boolean desktopMode,
      @Value("${toolbox.auth.synchronize-desktop-admin-password:false}")
          boolean synchronizeDesktopPassword,
      @Value("${toolbox.auth.allow-insecure-development-credentials:false}")
          boolean allowInsecureDevelopmentCredentials,
      @Value("${toolbox.auth.migrate-legacy-development-credentials:false}")
          boolean migrateLegacyDevelopmentCredentials,
      ObjectProvider<MitmCertificateAuthority> certificateAuthority) {
    this.users = users;
    this.encoder = encoder;
    this.password = password;
    this.desktopMode = desktopMode;
    this.synchronizeDesktopPassword = synchronizeDesktopPassword;
    this.allowInsecureDevelopmentCredentials = allowInsecureDevelopmentCredentials;
    this.migrateLegacyDevelopmentCredentials = migrateLegacyDevelopmentCredentials;
    this.certificateAuthority = certificateAuthority::getIfAvailable;
  }

  DefaultAdminInitializer(
      UserRepository users,
      PasswordEncoder encoder,
      String password,
      boolean desktopMode,
      boolean synchronizeDesktopPassword,
      boolean allowInsecureDevelopmentCredentials) {
    this(
        users,
        encoder,
        password,
        desktopMode,
        synchronizeDesktopPassword,
        allowInsecureDevelopmentCredentials,
        false,
        (MitmCertificateAuthority) null);
  }

  DefaultAdminInitializer(
      UserRepository users,
      PasswordEncoder encoder,
      String password,
      boolean desktopMode,
      boolean synchronizeDesktopPassword,
      boolean allowInsecureDevelopmentCredentials,
      boolean migrateLegacyDevelopmentCredentials,
      MitmCertificateAuthority certificateAuthority) {
    this(
        users,
        encoder,
        password,
        desktopMode,
        synchronizeDesktopPassword,
        allowInsecureDevelopmentCredentials,
        migrateLegacyDevelopmentCredentials,
        new FixedObjectProvider(certificateAuthority));
  }

  @Override
  @Transactional
  public void run(ApplicationArguments args) {
    if (password == null || password.isBlank()) {
      throw new IllegalStateException("管理员密码不能为空");
    }
    if (LEGACY_DEVELOPMENT_PASSWORD.equals(password) && !allowInsecureDevelopmentCredentials) {
      throw new IllegalStateException("默认管理员密码已禁用，请将 ADMIN_PASSWORD 设置为高强度密码");
    }

    User admin = users.findByUsername("admin").orElse(null);
    if (migrateLegacyDevelopmentCredentials) {
      migrateLegacyDevelopmentCredentials(admin);
      return;
    }
    if (admin == null) {
      admin = new User();
      admin.setUsername("admin");
      admin.setPasswordHash(encoder.encode(password));
      admin.setRole("ADMIN");
      users.save(admin);
    }
    // The desktop admin password is seeded only on first creation and is deliberately NOT
    // re-synced on every launch. This lets a password the user sets in 系统设置 → 修改登录密码
    // persist across restarts so account/password login keeps working. (First launch still
    // uses the auto-generated local credential via 本机安全凭据 / Windows Hello.)
    boolean desktopManaged = desktopMode && synchronizeDesktopPassword;
    if (desktopManaged) {
      log.info("桌面端管理员凭据由用户管理，已跳过本次启动时的密码同步");
    }

    if (LEGACY_DEVELOPMENT_PASSWORD.equals(password)) {
      log.warn("当前正在使用默认开发管理员密码，部署前请设置 ADMIN_PASSWORD");
    }
  }

  private void migrateLegacyDevelopmentCredentials(User admin) {
    if (password.length() < 16) {
      throw new IllegalStateException("迁移旧版管理员凭据时，新密码长度不得少于 16 个字符");
    }
    if (admin == null) {
      throw new IllegalStateException("迁移旧版开发凭据需要现有的管理员账户");
    }
    MitmCertificateAuthority authority = certificateAuthority.get();
    if (authority == null || !authority.enabled()) {
      throw new IllegalStateException("迁移旧版开发凭据需要现有的 HTTPS 中间人（MITM）证书颁发机构");
    }

    boolean adminUsesConfiguredPassword = encoder.matches(password, admin.getPasswordHash());
    boolean adminUsesLegacyPassword =
        !adminUsesConfiguredPassword
            && encoder.matches(LEGACY_DEVELOPMENT_PASSWORD, admin.getPasswordHash());
    boolean caUsesConfiguredPassword = authority.usesConfiguredPassword();
    boolean caUsesLegacyPassword = authority.usesLegacyDevelopmentPassword();

    // Validate both stores before changing either one. Configured values are accepted so an
    // interrupted first attempt can safely finish the remaining half on the next launch.
    if (!adminUsesConfiguredPassword && !adminUsesLegacyPassword) {
      throw new IllegalStateException("现有管理员凭据不是旧版开发默认值，未执行迁移");
    }
    if (!caUsesConfiguredPassword && !caUsesLegacyPassword) {
      throw new IllegalStateException("现有 HTTPS 中间人证书颁发机构未使用旧版或当前配置密码，未执行迁移");
    }

    String migratedHash = adminUsesLegacyPassword ? encoder.encode(password) : null;
    if (caUsesLegacyPassword) {
      authority.migrateLegacyDevelopmentPassword();
    }
    if (adminUsesLegacyPassword) {
      admin.setPasswordHash(migratedHash);
      users.saveAndFlush(admin);
    }
    log.info("旧版开发凭据已迁移为受保护的生成值");
  }

  private static final class FixedObjectProvider
      implements ObjectProvider<MitmCertificateAuthority> {
    private final MitmCertificateAuthority value;

    private FixedObjectProvider(MitmCertificateAuthority value) {
      this.value = value;
    }

    @Override
    public MitmCertificateAuthority getObject(Object... args) {
      return value;
    }

    @Override
    public MitmCertificateAuthority getIfAvailable() {
      return value;
    }

    @Override
    public MitmCertificateAuthority getObject() {
      return value;
    }
  }
}
