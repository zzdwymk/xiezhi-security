package com.bachelor.toolbox.traffic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MitmCertificateAuthorityTests {
  private static final String PASSWORD = "test-ca-password";
  private static final String MIGRATED_PASSWORD = "generated-test-ca-password";

  @TempDir Path temporaryDirectory;

  @Test
  void persistsAndReloadsTheSameRootCertificate() throws Exception {
    Path storePath = temporaryDirectory.resolve("nested/traffic-ca.p12");

    MitmCertificateAuthority first =
        new MitmCertificateAuthority(true, storePath.toString(), PASSWORD);
    MitmCertificateAuthority second =
        new MitmCertificateAuthority(true, storePath.toString(), PASSWORD);

    assertTrue(Files.isRegularFile(storePath));
    assertTrue(first.enabled());
    assertEquals(64, first.fingerprint().length());
    assertTrue(first.fingerprint().matches("[0-9A-F]{64}"));
    assertEquals(first.fingerprint(), second.fingerprint());
    X509Certificate root = loadRootCertificate(storePath);
    assertTrue(root.getBasicConstraints() >= 0);
    root.verify(root.getPublicKey());
  }

  @Test
  void createsSignedDnsLeafWithServerAuthAndCachesItsContext() throws Exception {
    Path storePath = temporaryDirectory.resolve("traffic-ca.p12");
    MitmCertificateAuthority authority =
        new MitmCertificateAuthority(true, storePath.toString(), PASSWORD);

    SSLContext first = authority.serverContext("Example.TEST.");
    SSLContext second = authority.serverContext("example.test");
    X509Certificate leaf = handshakeAndReadLeaf(first, loadRootCertificate(storePath));

    assertSame(first, second);
    assertEquals(-1, leaf.getBasicConstraints());
    leaf.verify(loadRootCertificate(storePath).getPublicKey());
    assertSan(leaf, 2, "example.test");
    assertTrue(leaf.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.1"));
  }

  @Test
  void createsIpAddressSubjectAlternativeName() throws Exception {
    Path storePath = temporaryDirectory.resolve("traffic-ca.p12");
    MitmCertificateAuthority authority =
        new MitmCertificateAuthority(true, storePath.toString(), PASSWORD);

    X509Certificate leaf =
        handshakeAndReadLeaf(authority.serverContext("127.0.0.1"), loadRootCertificate(storePath));

    assertSan(leaf, 7, "127.0.0.1");
  }

  @Test
  void disabledAuthorityDoesNotCreateOrServeCertificates() {
    Path storePath = temporaryDirectory.resolve("disabled-ca.p12");

    MitmCertificateAuthority authority =
        new MitmCertificateAuthority(false, storePath.toString(), PASSWORD);

    assertFalse(authority.enabled());
    assertEquals("", authority.fingerprint());
    assertFalse(Files.exists(storePath));
    assertThrows(IllegalStateException.class, () -> authority.serverContext("example.test"));
  }

  @Test
  void enabledAuthorityFailsFastForAnUnreadableStore() throws Exception {
    Path storePath = temporaryDirectory.resolve("invalid-ca.p12");
    Files.writeString(storePath, "not a PKCS12 store");

    assertThrows(
        IllegalStateException.class,
        () -> new MitmCertificateAuthority(true, storePath.toString(), PASSWORD));
  }

  @Test
  void rejectsFixedDevelopmentPasswordWithoutExplicitOptIn() {
    Path storePath = temporaryDirectory.resolve("default-password-ca.p12");

    IllegalStateException error =
        assertThrows(
            IllegalStateException.class,
            () ->
                new MitmCertificateAuthority(
                    true,
                    storePath.toString(),
                    MitmCertificateAuthority.DEVELOPMENT_PASSWORD,
                    false));

    assertTrue(error.getMessage().contains("默认 HTTPS MITM CA 密码已禁用"));
    assertFalse(Files.exists(storePath));
  }

  @Test
  void allowsFixedDevelopmentPasswordOnlyWithExplicitOptIn() {
    Path storePath = temporaryDirectory.resolve("explicit-development-ca.p12");

    MitmCertificateAuthority authority =
        new MitmCertificateAuthority(
            true, storePath.toString(), MitmCertificateAuthority.DEVELOPMENT_PASSWORD, true);

    assertTrue(authority.enabled());
    assertTrue(Files.isRegularFile(storePath));
  }

  @Test
  void migratesLegacyStorePasswordWithoutChangingRootMaterial() throws Exception {
    Path storePath = temporaryDirectory.resolve("legacy-ca.p12");
    new MitmCertificateAuthority(
        true, storePath.toString(), MitmCertificateAuthority.DEVELOPMENT_PASSWORD, true);
    StoredRoot before = loadRoot(storePath, MitmCertificateAuthority.DEVELOPMENT_PASSWORD);

    MitmCertificateAuthority migration =
        new MitmCertificateAuthority(true, storePath.toString(), MIGRATED_PASSWORD, false, true);

    assertTrue(migration.usesLegacyDevelopmentPassword());
    assertFalse(migration.usesConfiguredPassword());
    assertThrows(Exception.class, () -> loadRoot(storePath, MIGRATED_PASSWORD));

    migration.migrateLegacyDevelopmentPassword();

    StoredRoot after = loadRoot(storePath, MIGRATED_PASSWORD);
    assertArrayEquals(before.privateKey().getEncoded(), after.privateKey().getEncoded());
    assertEquals(before.certificate(), after.certificate());
    assertEquals(before.certificate().getPublicKey(), after.certificate().getPublicKey());
    assertFalse(migration.usesLegacyDevelopmentPassword());
    assertTrue(migration.usesConfiguredPassword());
    assertThrows(
        Exception.class, () -> loadRoot(storePath, MitmCertificateAuthority.DEVELOPMENT_PASSWORD));
  }

  @Test
  void failedLegacyPasswordValidationLeavesExistingStoreUntouched() throws Exception {
    Path storePath = temporaryDirectory.resolve("non-legacy-ca.p12");
    String existingPassword = "different-existing-password";
    new MitmCertificateAuthority(true, storePath.toString(), existingPassword);
    byte[] before = Files.readAllBytes(storePath);

    assertThrows(
        IllegalStateException.class,
        () ->
            new MitmCertificateAuthority(
                true, storePath.toString(), MIGRATED_PASSWORD, false, true));

    assertArrayEquals(before, Files.readAllBytes(storePath));
    assertTrue(loadRoot(storePath, existingPassword).certificate().getBasicConstraints() >= 0);
  }

  @Test
  void legacyMigrationRequiresAnExistingStore() {
    Path storePath = temporaryDirectory.resolve("missing-legacy-ca.p12");

    IllegalStateException error =
        assertThrows(
            IllegalStateException.class,
            () ->
                new MitmCertificateAuthority(
                    true, storePath.toString(), MIGRATED_PASSWORD, false, true));

    assertTrue(error.getMessage().contains("无法初始化 HTTPS MITM 证书颁发机构"));
    assertFalse(Files.exists(storePath));
  }

  private X509Certificate loadRootCertificate(Path storePath) throws Exception {
    return loadRoot(storePath, PASSWORD).certificate();
  }

  private StoredRoot loadRoot(Path storePath, String password) throws Exception {
    KeyStore store = KeyStore.getInstance("PKCS12");
    try (InputStream input = Files.newInputStream(storePath)) {
      store.load(input, password.toCharArray());
    }
    KeyStore.PrivateKeyEntry entry =
        (KeyStore.PrivateKeyEntry)
            store.getEntry(
                "traffic-mitm-root", new KeyStore.PasswordProtection(password.toCharArray()));
    return new StoredRoot(entry.getPrivateKey(), (X509Certificate) entry.getCertificate());
  }

  private X509Certificate handshakeAndReadLeaf(SSLContext serverContext, X509Certificate root)
      throws Exception {
    SSLContext clientContext = clientContextTrusting(root);
    ExecutorService worker = Executors.newSingleThreadExecutor();
    try (SSLServerSocket server =
        (SSLServerSocket)
            serverContext
                .getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
      Future<?> serverHandshake =
          worker.submit(
              () -> {
                try (SSLSocket socket = (SSLSocket) server.accept()) {
                  socket.setUseClientMode(false);
                  socket.setSoTimeout(5_000);
                  socket.startHandshake();
                  socket.getInputStream().read();
                } catch (Exception ex) {
                  throw new RuntimeException(ex);
                }
              });
      X509Certificate leaf;
      try (SSLSocket client =
          (SSLSocket)
              clientContext
                  .getSocketFactory()
                  .createSocket(InetAddress.getLoopbackAddress(), server.getLocalPort())) {
        client.setSoTimeout(5_000);
        client.startHandshake();
        leaf = (X509Certificate) client.getSession().getPeerCertificates()[0];
        client.getOutputStream().write(1);
        client.getOutputStream().flush();
      }
      serverHandshake.get(5, TimeUnit.SECONDS);
      return leaf;
    } finally {
      worker.shutdownNow();
    }
  }

  private SSLContext clientContextTrusting(X509Certificate root) throws Exception {
    KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, null);
    trustStore.setCertificateEntry("root", root);
    TrustManagerFactory trustManagers =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagers.init(trustStore);
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(null, trustManagers.getTrustManagers(), null);
    return context;
  }

  private void assertSan(X509Certificate certificate, int expectedType, String expectedValue)
      throws Exception {
    Collection<List<?>> names = certificate.getSubjectAlternativeNames();
    assertTrue(
        names.stream()
            .anyMatch(
                name ->
                    expectedType == (Integer) name.get(0)
                        && expectedValue.equalsIgnoreCase(String.valueOf(name.get(1)))));
  }

  private record StoredRoot(PrivateKey privateKey, X509Certificate certificate) {}
}
