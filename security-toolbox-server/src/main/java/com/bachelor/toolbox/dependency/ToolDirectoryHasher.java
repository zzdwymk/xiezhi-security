package com.bachelor.toolbox.dependency;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 对 tools 下单个工具目录生成内容哈希并写入该目录的 {@value #HASH_FILE}。
 *
 * <p>为保证「检测完生成哈希 → 主动检测时重算比对」能成立，重算时必须排除 {@value #HASH_FILE}
 * 自身：该文件内容会随哈希变化，若不排除则每次重算都不可能一致。目录其余内容不变时，重算哈希
 * 应与已写入的值一致。
 */
@Component
public class ToolDirectoryHasher {
  private static final Logger log = LoggerFactory.getLogger(ToolDirectoryHasher.class);

  /** 保留的哈希文件，计算时须排除，避免自指导致哈希永不收敛。 */
  public static final String HASH_FILE = ".toolbox-hash";

  /** 计算并写入工具目录哈希。目录不存在或其中无普通文件时返回 null 且不写入。 */
  public String hashDirectory(Path directory) {
    try {
      String hex = computeHash(directory);
      if (hex == null) {
        return null;
      }
      Path hashFile = directory.resolve(HASH_FILE);
      Files.writeString(hashFile, hex, StandardCharsets.UTF_8);
      return hex;
    } catch (IOException ex) {
      log.warn("写入工具目录哈希失败，dir={}", directory, ex);
      return null;
    }
  }

  /** 计算工具目录内容哈希（不写入、排除 {@link #HASH_FILE}）。目录不存在或其中无普通文件返回 null。 */
  public String computeHash(Path directory) {
    try {
      byte[] digest = computeDigest(directory);
      return digest == null ? null : HexFormat.of().formatHex(digest);
    } catch (IOException ex) {
      log.debug("计算工具目录哈希失败，dir={}", directory, ex);
      return null;
    }
  }

  /** 重算目录哈希并与已记录的 {HASH_FILE} 比对，一致表示该扫描器目录未发生变化。 */
  public boolean matches(Path directory) {
    String recorded = readHash(directory);
    if (recorded == null || recorded.isBlank()) {
      return false;
    }
    String current = computeHash(directory);
    return current != null && current.equals(recorded);
  }

  /**
   * 带有「留时生成 + 重试」的比对：tools 目录可能正被写入（检测刚落盘 / 扫描器写缓存），
   * 直接重算会读到未就绪的中间值造成误报。这里先等待并重试几次，让哈希落盘稳定后再判定，
   * 只有重试耗尽仍不一致才返回 false。
   *
   * @param settleDelay 每次等待稳定所需的时间
   * @param attempts 最多尝试次数（含首次）
   */
  public boolean matchesWithRetry(Path directory, java.time.Duration settleDelay, int attempts) {
    for (int i = 0; i < attempts; i++) {
      if (matches(directory)) {
        return true;
      }
      // 哈希文件尚未生成，或目录正被写入读到未就绪的中间值：留时间稳定后再试。
      if (i == attempts - 1) {
        break;
      }
      sleep(settleDelay);
    }
    // 重试耗尽后做最后一次判定：哈希文件存在且重算一致才通过。
    String recorded = readHash(directory);
    String current = computeHash(directory);
    return recorded != null && !recorded.isBlank() && current != null && current.equals(recorded);
  }

  private void sleep(java.time.Duration delay) {
    try {
      Thread.sleep(delay.toMillis());
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
    }
  }

  /** 读取已写入的工具目录哈希，不存在或不可读返回 null。 */
  public String readHash(Path directory) {
    try {
      Path hashFile = directory.resolve(HASH_FILE);
      if (!Files.isRegularFile(hashFile)) {
        return null;
      }
      return Files.readString(hashFile, StandardCharsets.UTF_8).trim();
    } catch (IOException ex) {
      log.debug("读取工具目录哈希失败，dir={}", directory, ex);
      return null;
    }
  }

  private byte[] computeDigest(Path directory) throws IOException {
    if (!Files.isDirectory(directory)) {
      return null;
    }
    return shaDigest(directory);
  }

  private byte[] shaDigest(Path directory) throws IOException {
    List<Path> files;
    try (Stream<Path> stream = Files.walk(directory)) {
      files =
          stream
              .filter(Files::isRegularFile)
              .filter(p -> !HASH_FILE.equals(p.getFileName().toString()))
              .sorted()
              .toList();
    }
    if (files.isEmpty()) {
      return null;
    }
    MessageDigest md = newDigest();
    for (Path file : files) {
      String relative =
          file.toString().substring(directory.toString().length()).replace('\\', '/').replaceFirst("^/", "");
      md.update(relative.getBytes(StandardCharsets.UTF_8));
      md.update((byte) 0);
      md.update(String.valueOf(Files.size(file)).getBytes(StandardCharsets.UTF_8));
      md.update((byte) 0);
      md.update(sha256(file));
    }
    return md.digest();
  }

  private static MessageDigest newDigest() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (Exception ex) {
      throw new IllegalStateException("SHA-256 不可用", ex);
    }
  }

  private byte[] sha256(Path file) throws IOException {
    try (InputStream in = Files.newInputStream(file)) {
      MessageDigest md = newDigest();
      byte[] buffer = new byte[8192];
      int read;
      while ((read = in.read(buffer)) != -1) {
        md.update(buffer, 0, read);
      }
      return md.digest();
    }
  }
}