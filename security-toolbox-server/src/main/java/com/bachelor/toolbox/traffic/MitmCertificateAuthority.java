package com.bachelor.toolbox.traffic;

import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.IDN;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Owns the local certificate authority used only by the isolated traffic-capture browser. The root
 * private key remains in the configured PKCS#12 file and is never exposed by this API.
 */
@Component
public class MitmCertificateAuthority {
  private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;
  private static final String ROOT_ALIAS = "traffic-mitm-root";
  private static final String LEAF_ALIAS = "traffic-mitm-leaf";
  static final String DEVELOPMENT_PASSWORD = "change-this-development-password";
  private static final int CONTEXT_CACHE_SIZE = 128;
  private static final Object ROOT_STORE_LOCK = new Object();
  private static final SecureRandom RANDOM = new SecureRandom();

  static {
    if (Security.getProvider(PROVIDER) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private final boolean enabled;
  private final Path caPath;
  private final char[] password;
  private final PrivateKey rootPrivateKey;
  private final X509Certificate rootCertificate;
  private final String fingerprint;
  private volatile RootStoreCredentialState rootStoreCredentialState;
  private final Map<String, SSLContext> contexts =
      new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, SSLContext> eldest) {
          return size() > CONTEXT_CACHE_SIZE;
        }
      };

  public MitmCertificateAuthority(boolean enabled, String caPath, String password) {
    this(enabled, caPath, password, false, false);
  }

  public MitmCertificateAuthority(
      boolean enabled,
      String caPath,
      String password,
      boolean allowInsecureDevelopmentCredentials) {
    this(enabled, caPath, password, allowInsecureDevelopmentCredentials, false);
  }

  @Autowired
  public MitmCertificateAuthority(
      @Value("${toolbox.traffic.mitm-enabled:true}") boolean enabled,
      @Value("${toolbox.traffic.mitm-ca-path:./data/traffic-mitm-ca.p12}") String caPath,
      @Value("${toolbox.traffic.mitm-ca-password:change-this-development-password}")
          String password,
      @Value("${toolbox.auth.allow-insecure-development-credentials:false}")
          boolean allowInsecureDevelopmentCredentials,
      @Value("${toolbox.auth.migrate-legacy-development-credentials:false}")
          boolean migrateLegacyDevelopmentCredentials) {
    this.enabled = enabled;
    this.caPath = Path.of(caPath).toAbsolutePath().normalize();
    this.password = password == null ? new char[0] : password.toCharArray();

    if (!enabled) {
      this.rootPrivateKey = null;
      this.rootCertificate = null;
      this.fingerprint = "";
      this.rootStoreCredentialState = RootStoreCredentialState.DISABLED;
      return;
    }
    if (DEVELOPMENT_PASSWORD.equals(password) && !allowInsecureDevelopmentCredentials) {
      Arrays.fill(this.password, '\0');
      throw new IllegalStateException(
          "默认 HTTPS MITM CA 密码已禁用，请通过 TRAFFIC_MITM_CA_PASSWORD 设置高强度密码");
    }
    if (this.password.length == 0) {
      throw new IllegalStateException("HTTPS MITM CA 密码不能为空");
    }
    if (migrateLegacyDevelopmentCredentials && this.password.length < 16) {
      Arrays.fill(this.password, '\0');
      throw new IllegalStateException("迁移旧版 HTTPS MITM CA 时，新密码至少需要 16 个字符");
    }

    try {
      RootMaterial material;
      synchronized (ROOT_STORE_LOCK) {
        if (Files.exists(this.caPath)) {
          try {
            material = loadRoot(this.caPath, this.password);
            this.rootStoreCredentialState = RootStoreCredentialState.CONFIGURED;
          } catch (Exception configuredPasswordFailure) {
            if (!migrateLegacyDevelopmentCredentials) {
              throw configuredPasswordFailure;
            }
            char[] legacyPassword = DEVELOPMENT_PASSWORD.toCharArray();
            try {
              material = loadRoot(this.caPath, legacyPassword);
              this.rootStoreCredentialState = RootStoreCredentialState.LEGACY_DEVELOPMENT;
            } catch (Exception legacyPasswordFailure) {
              configuredPasswordFailure.addSuppressed(legacyPasswordFailure);
              throw configuredPasswordFailure;
            } finally {
              Arrays.fill(legacyPassword, '\0');
            }
          }
        } else {
          if (migrateLegacyDevelopmentCredentials) {
            throw new IllegalStateException("迁移旧版 HTTPS MITM CA 需要已有的 PKCS#12 存储文件");
          }
          material = createAndPersistRoot();
          this.rootStoreCredentialState = RootStoreCredentialState.CONFIGURED;
        }
      }
      this.rootPrivateKey = material.privateKey();
      this.rootCertificate = material.certificate();
      this.fingerprint = sha256Fingerprint(rootCertificate);
    } catch (Exception ex) {
      Arrays.fill(this.password, '\0');
      throw new IllegalStateException("无法初始化 HTTPS MITM 证书颁发机构：" + this.caPath, ex);
    }
  }

  public boolean enabled() {
    return enabled;
  }

  /**
   * Returns the root certificate SHA-256 fingerprint as uppercase hexadecimal without separators.
   */
  public String fingerprint() {
    return fingerprint;
  }

  public boolean usesLegacyDevelopmentPassword() {
    return rootStoreCredentialState == RootStoreCredentialState.LEGACY_DEVELOPMENT;
  }

  public boolean usesConfiguredPassword() {
    return rootStoreCredentialState == RootStoreCredentialState.CONFIGURED;
  }

  /**
   * Re-encrypts an already validated legacy root store without changing its CA key or certificate.
   * A temporary store is verified before it atomically replaces the original.
   */
  public void migrateLegacyDevelopmentPassword() {
    if (!enabled) {
      throw new IllegalStateException("HTTPS MITM 功能已禁用");
    }
    synchronized (ROOT_STORE_LOCK) {
      if (rootStoreCredentialState == RootStoreCredentialState.CONFIGURED) {
        return;
      }
      if (rootStoreCredentialState != RootStoreCredentialState.LEGACY_DEVELOPMENT) {
        throw new IllegalStateException("HTTPS MITM CA 尚未准备好迁移旧版凭据");
      }
      try {
        RootMaterial material = new RootMaterial(rootPrivateKey, rootCertificate);
        KeyStore replacement = KeyStore.getInstance("PKCS12");
        replacement.load(null, password);
        replacement.setKeyEntry(
            ROOT_ALIAS, rootPrivateKey, password, new Certificate[] {rootCertificate});
        persist(replacement, material, true);
        rootStoreCredentialState = RootStoreCredentialState.CONFIGURED;
      } catch (Exception ex) {
        throw new IllegalStateException("无法迁移旧版 HTTPS MITM CA 密码：" + caPath, ex);
      }
    }
  }

  /**
   * Returns a TLS server context whose leaf certificate is valid for the supplied DNS name or IP
   * literal.
   */
  public SSLContext serverContext(String host) {
    if (!enabled) {
      throw new IllegalStateException("HTTPS MITM 功能已禁用");
    }
    String normalized = normalizeHost(host);
    synchronized (contexts) {
      SSLContext existing = contexts.get(normalized);
      if (existing != null) {
        return existing;
      }
      try {
        SSLContext created = createServerContext(normalized);
        contexts.put(normalized, created);
        return created;
      } catch (Exception ex) {
        throw new IllegalStateException("无法为目标创建 HTTPS MITM 证书：" + normalized, ex);
      }
    }
  }

  private RootMaterial loadRoot(Path storePath, char[] storePassword) throws Exception {
    KeyStore store = KeyStore.getInstance("PKCS12");
    try (InputStream input = Files.newInputStream(storePath)) {
      store.load(input, storePassword);
    }
    KeyStore.Entry entry =
        store.getEntry(ROOT_ALIAS, new KeyStore.PasswordProtection(storePassword));
    if (!(entry instanceof KeyStore.PrivateKeyEntry privateKeyEntry)
        || !(privateKeyEntry.getCertificate() instanceof X509Certificate certificate)) {
      throw new IllegalStateException("PKCS#12 中缺少预期的根 CA 条目");
    }
    certificate.checkValidity();
    if (certificate.getBasicConstraints() < 0) {
      throw new IllegalStateException("存储的证书不是有效的证书颁发机构");
    }
    certificate.verify(certificate.getPublicKey());
    return new RootMaterial(privateKeyEntry.getPrivateKey(), certificate);
  }

  private RootMaterial createAndPersistRoot() throws Exception {
    KeyPair keyPair = generateRsaKeyPair(3072);
    Instant now = Instant.now();
    X500Name name =
        new X500NameBuilder(BCStyle.INSTANCE)
            .addRDN(BCStyle.CN, "Xiezhi Local HTTPS MITM CA")
            .addRDN(BCStyle.O, "Xiezhi")
            .build();
    JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
    SubjectKeyIdentifier subjectKeyIdentifier =
        extensionUtils.createSubjectKeyIdentifier(keyPair.getPublic());
    AuthorityKeyIdentifier authorityKeyIdentifier =
        extensionUtils.createAuthorityKeyIdentifier(keyPair.getPublic());
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            name,
            randomSerial(),
            java.util.Date.from(now.minus(1, ChronoUnit.DAYS)),
            java.util.Date.from(now.plus(5 * 365L, ChronoUnit.DAYS)),
            name,
            keyPair.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    builder.addExtension(
        Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
    builder.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
    builder.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
    X509Certificate certificate = sign(builder, keyPair.getPrivate());
    certificate.verify(keyPair.getPublic());

    KeyStore store = KeyStore.getInstance("PKCS12");
    store.load(null, password);
    store.setKeyEntry(ROOT_ALIAS, keyPair.getPrivate(), password, new Certificate[] {certificate});
    RootMaterial material = new RootMaterial(keyPair.getPrivate(), certificate);
    persist(store, material, false);
    return material;
  }

  private void persist(KeyStore store, RootMaterial expected, boolean replaceExisting)
      throws Exception {
    Path parent = caPath.getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
    Path temporary = Files.createTempFile(parent, caPath.getFileName().toString(), ".tmp");
    boolean moved = false;
    try {
      try (OutputStream output = Files.newOutputStream(temporary)) {
        store.store(output, password);
      }
      RootMaterial written = loadRoot(temporary, password);
      if (!Arrays.equals(expected.privateKey().getEncoded(), written.privateKey().getEncoded())
          || !expected.certificate().equals(written.certificate())) {
        throw new IllegalStateException("写入的 PKCS#12 根证书材料与源数据不一致");
      }
      try {
        if (replaceExisting) {
          Files.move(
              temporary,
              caPath,
              StandardCopyOption.ATOMIC_MOVE,
              StandardCopyOption.REPLACE_EXISTING);
        } else {
          Files.move(temporary, caPath, StandardCopyOption.ATOMIC_MOVE);
        }
      } catch (AtomicMoveNotSupportedException ex) {
        if (replaceExisting) {
          throw new IllegalStateException("CA 所在文件系统不支持原子凭据迁移", ex);
        } else {
          Files.move(temporary, caPath);
        }
      }
      moved = true;
    } finally {
      if (!moved) {
        Files.deleteIfExists(temporary);
      }
    }
  }

  private SSLContext createServerContext(String host) throws Exception {
    KeyPair leafKey = generateRsaKeyPair(2048);
    Instant now = Instant.now();
    X500Name issuer = X500Name.getInstance(rootCertificate.getSubjectX500Principal().getEncoded());
    X500Name subject = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, host).build();
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            issuer,
            randomSerial(),
            java.util.Date.from(now.minus(5, ChronoUnit.MINUTES)),
            java.util.Date.from(now.plus(30, ChronoUnit.DAYS)),
            subject,
            leafKey.getPublic());
    JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
    int generalNameType = isIpLiteral(host) ? GeneralName.iPAddress : GeneralName.dNSName;
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
    builder.addExtension(
        Extension.keyUsage,
        true,
        new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
    builder.addExtension(
        Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
    builder.addExtension(
        Extension.subjectAlternativeName,
        false,
        new GeneralNames(new GeneralName(generalNameType, host)));
    builder.addExtension(
        Extension.subjectKeyIdentifier,
        false,
        extensionUtils.createSubjectKeyIdentifier(leafKey.getPublic()));
    builder.addExtension(
        Extension.authorityKeyIdentifier,
        false,
        extensionUtils.createAuthorityKeyIdentifier(rootCertificate));
    X509Certificate leafCertificate = sign(builder, rootPrivateKey);
    leafCertificate.verify(rootCertificate.getPublicKey());

    KeyStore leafStore = KeyStore.getInstance("PKCS12");
    leafStore.load(null, password);
    leafStore.setKeyEntry(
        LEAF_ALIAS,
        leafKey.getPrivate(),
        password,
        new Certificate[] {leafCertificate, rootCertificate});
    KeyManagerFactory keyManagers =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagers.init(leafStore, password);
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(keyManagers.getKeyManagers(), null, RANDOM);
    return context;
  }

  private X509Certificate sign(JcaX509v3CertificateBuilder builder, PrivateKey signingKey)
      throws Exception {
    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withRSA").setProvider(PROVIDER).build(signingKey);
    X509CertificateHolder holder = builder.build(signer);
    return new JcaX509CertificateConverter().setProvider(PROVIDER).getCertificate(holder);
  }

  private KeyPair generateRsaKeyPair(int bits) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", PROVIDER);
    generator.initialize(bits, RANDOM);
    return generator.generateKeyPair();
  }

  private BigInteger randomSerial() {
    return new BigInteger(160, RANDOM).setBit(159);
  }

  private String normalizeHost(String host) {
    if (host == null || host.isBlank()) {
      throw new IllegalArgumentException("证书主机名不能为空");
    }
    String normalized = host.trim();
    if (normalized.startsWith("[") && normalized.endsWith("]")) {
      normalized = normalized.substring(1, normalized.length() - 1);
    }
    if (normalized.endsWith(".")) {
      normalized = normalized.substring(0, normalized.length() - 1);
    }
    if (normalized.isBlank()) {
      throw new IllegalArgumentException("证书主机名不能为空");
    }
    if (!isIpLiteral(normalized)) {
      normalized = IDN.toASCII(normalized, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
      if (normalized.length() > 253) {
        throw new IllegalArgumentException("证书 DNS 名称过长");
      }
    }
    return normalized;
  }

  private boolean isIpLiteral(String host) {
    if (host.indexOf(':') >= 0) {
      return true;
    }
    String[] parts = host.split("\\.", -1);
    if (parts.length != 4) {
      return false;
    }
    for (String part : parts) {
      if (part.isEmpty() || part.length() > 3) {
        return false;
      }
      try {
        int value = Integer.parseInt(part);
        if (value < 0 || value > 255) {
          return false;
        }
      } catch (NumberFormatException ex) {
        return false;
      }
    }
    return true;
  }

  private String sha256Fingerprint(X509Certificate certificate) throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
    return HexFormat.of().withUpperCase().formatHex(digest);
  }

  private record RootMaterial(PrivateKey privateKey, X509Certificate certificate) {}

  private enum RootStoreCredentialState {
    DISABLED,
    CONFIGURED,
    LEGACY_DEVELOPMENT
  }
}
