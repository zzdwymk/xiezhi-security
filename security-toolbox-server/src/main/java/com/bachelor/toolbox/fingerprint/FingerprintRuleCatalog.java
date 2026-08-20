package com.bachelor.toolbox.fingerprint;

import com.bachelor.toolbox.common.ApiException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

@Service
public class FingerprintRuleCatalog {
  private static final Logger log = LoggerFactory.getLogger(FingerprintRuleCatalog.class);
  static final int MAX_BYTES = 2 * 1024 * 1024;
  private static final int MAX_RULES = 10_000;
  private static final Pattern RULE_ID = Pattern.compile("[a-z0-9][a-z0-9._-]{0,79}");
  private static final String BUILTIN_RESOURCE = "fingerprints/default-rules.json";

  private final ObjectMapper mapper;
  private final Path externalFile;
  private final Path managedFile;
  private volatile LoadedCatalog loadedCatalog;

  @Autowired
  public FingerprintRuleCatalog(
      ObjectMapper mapper,
      @Value("${toolbox.fingerprints.rules-file:}") String externalFile,
      @Value("${toolbox.fingerprints.managed-rules-file:./data/fingerprints/rules.json}")
          String managedFile) {
    this.mapper = mapper;
    this.externalFile = configuredPath(externalFile);
    this.managedFile = requiredManagedPath(managedFile);
  }

  /** Retains the constructor used by catalog unit tests and existing embedders. */
  public FingerprintRuleCatalog(ObjectMapper mapper, String externalFile) {
    this(mapper, externalFile, "./data/fingerprints/rules.json");
  }

  @PostConstruct
  public void load() {
    reload();
  }

  public synchronized CatalogInfo reload() {
    try {
      LoadedCatalog candidate = loadCatalog();
      loadedCatalog = candidate;
      return info(candidate);
    } catch (ApiException ex) {
      log.warn("指纹规则校验失败，source={}", configuredSourceDescription());
      throw ex;
    } catch (Exception ex) {
      log.error(
          "加载指纹规则失败，source={}，errorType={}",
          configuredSourceDescription(),
          ex.getClass().getSimpleName());
      throw new ApiException("无法加载指纹规则，请检查规则文件后重试");
    }
  }

  /**
   * Validates and installs a complete catalog. The currently loaded catalog is only swapped after
   * the new file has been validated, persisted and read back successfully.
   */
  public synchronized CatalogInfo update(byte[] bytes) {
    try {
      requireSupportedSize(bytes);
      CatalogSource source = externalFile == null ? CatalogSource.MANAGED : CatalogSource.EXTERNAL;
      LoadedCatalog candidate = parseCatalog(bytes, source);
      persistValidatedCatalog(updateTarget(), bytes, candidate);
      loadedCatalog = candidate;
      return info(candidate);
    } catch (ApiException ex) {
      log.warn("指纹规则更新校验失败，source={}", updateSourceDescription());
      throw ex;
    } catch (Exception ex) {
      log.error(
          "更新指纹规则失败，source={}，errorType={}",
          updateSourceDescription(),
          ex.getClass().getSimpleName());
      throw new ApiException("指纹规则更新失败，原有规则已保留");
    }
  }

  public CatalogInfo info() {
    return info(requireLoaded());
  }

  public List<Rule> rules() {
    return requireLoaded().catalog().rules();
  }

  private LoadedCatalog requireLoaded() {
    LoadedCatalog current = loadedCatalog;
    if (current == null) {
      throw new ApiException("指纹规则尚未加载");
    }
    return current;
  }

  private CatalogInfo info(LoadedCatalog current) {
    return new CatalogInfo(
        current.catalog().version(),
        current.sha256(),
        current.catalog().rules().size(),
        current.source());
  }

  private LoadedCatalog loadCatalog() throws Exception {
    if (externalFile != null) {
      return parseCatalog(readRuleFile(externalFile), CatalogSource.EXTERNAL);
    }
    if (Files.exists(managedFile, LinkOption.NOFOLLOW_LINKS)) {
      return parseCatalog(readRuleFile(managedFile), CatalogSource.MANAGED);
    }
    ClassPathResource resource = new ClassPathResource(BUILTIN_RESOURCE);
    try (InputStream input = resource.getInputStream()) {
      byte[] bytes = input.readNBytes(MAX_BYTES + 1);
      requireSupportedSize(bytes);
      return parseCatalog(bytes, CatalogSource.BUILTIN);
    }
  }

  private byte[] readRuleFile(Path file) throws IOException {
    if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
        || Files.size(file) > MAX_BYTES) {
      throw new ApiException("指纹规则文件不存在或超过 2MB 限制");
    }
    byte[] bytes = Files.readAllBytes(file);
    requireSupportedSize(bytes);
    return bytes;
  }

  private LoadedCatalog parseCatalog(byte[] bytes, CatalogSource source) throws Exception {
    Catalog parsed = mapper.readValue(bytes, Catalog.class);
    validate(parsed);
    Catalog immutableCatalog = new Catalog(parsed.version(), List.copyOf(parsed.rules()));
    return new LoadedCatalog(immutableCatalog, calculateSha256(bytes), source);
  }

  private void persistValidatedCatalog(Path target, byte[] bytes, LoadedCatalog expected)
      throws Exception {
    Path parent = requireSafeParent(target);
    Path temporary = Files.createTempFile(parent, ".fingerprint-rules-", ".json.tmp");
    boolean moved = false;
    try {
      Files.write(
          temporary,
          bytes,
          StandardOpenOption.TRUNCATE_EXISTING,
          StandardOpenOption.WRITE);
      LoadedCatalog written = parseCatalog(readRuleFile(temporary), expected.source());
      if (!expected.equals(written)) {
        throw new IOException("写入后的指纹规则与已校验内容不一致");
      }
      moveReplacing(temporary, target);
      moved = true;
    } finally {
      if (!moved) {
        Files.deleteIfExists(temporary);
      }
    }
  }

  private Path requireSafeParent(Path target) throws IOException {
    if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)
        && !Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
      throw new ApiException("指纹规则目标文件无效");
    }
    Path parent = target.getParent();
    if (parent == null) {
      throw new ApiException("指纹规则目标目录无效");
    }
    rejectSymbolicDirectoryComponents(parent);
    Files.createDirectories(parent);
    rejectSymbolicDirectoryComponents(parent);
    if (!Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
      throw new ApiException("指纹规则目标目录无效");
    }
    return parent;
  }

  private void rejectSymbolicDirectoryComponents(Path directory) {
    for (Path current = directory; current != null; current = current.getParent()) {
      if (!Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
        continue;
      }
      if (Files.isSymbolicLink(current)
          || !Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) {
        throw new ApiException("指纹规则目标目录不能包含符号链接或非目录节点");
      }
    }
  }

  private void moveReplacing(Path temporary, Path target) throws IOException {
    try {
      Files.move(
          temporary,
          target,
          StandardCopyOption.ATOMIC_MOVE,
          StandardCopyOption.REPLACE_EXISTING);
    } catch (AtomicMoveNotSupportedException ex) {
      moveReplacingWithBackup(temporary, target);
    }
  }

  private void moveReplacingWithBackup(Path temporary, Path target) throws IOException {
    Path backup = null;
    try {
      if (Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
        backup = Files.createTempFile(target.getParent(), ".fingerprint-rules-backup-", ".json");
        Files.copy(
            target,
            backup,
            StandardCopyOption.REPLACE_EXISTING,
            StandardCopyOption.COPY_ATTRIBUTES);
      }
      Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException moveFailure) {
      if (backup != null) {
        try {
          Files.copy(backup, target, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException restoreFailure) {
          moveFailure.addSuppressed(restoreFailure);
        }
      }
      throw moveFailure;
    } finally {
      if (backup != null) {
        try {
          Files.deleteIfExists(backup);
        } catch (IOException cleanupFailure) {
          log.warn("清理指纹规则更新备份失败，file={}", backup.getFileName(), cleanupFailure);
        }
      }
    }
  }

  private Path updateTarget() {
    return externalFile == null ? managedFile : externalFile;
  }

  private String configuredSourceDescription() {
    if (externalFile != null) {
      return "configured-file:" + externalFile.getFileName();
    }
    if (Files.exists(managedFile, LinkOption.NOFOLLOW_LINKS)) {
      return "managed:" + managedFile.getFileName();
    }
    return "classpath:" + BUILTIN_RESOURCE;
  }

  private String updateSourceDescription() {
    Path target = updateTarget();
    return (externalFile == null ? "managed:" : "configured-file:") + target.getFileName();
  }

  private static Path configuredPath(String value) {
    String normalized = value == null ? "" : value.trim();
    return normalized.isBlank() ? null : Path.of(normalized).toAbsolutePath().normalize();
  }

  private static Path requiredManagedPath(String value) {
    String normalized = value == null ? "" : value.trim();
    if (normalized.isBlank()) {
      throw new IllegalArgumentException("指纹规则托管文件路径不能为空");
    }
    return Path.of(normalized).toAbsolutePath().normalize();
  }

  private void requireSupportedSize(byte[] bytes) {
    if (bytes == null || bytes.length == 0) {
      throw new ApiException("指纹规则文件不能为空");
    }
    if (bytes.length > MAX_BYTES) {
      throw new ApiException("指纹规则文件超过 2MB 限制");
    }
  }

  private String calculateSha256(byte[] bytes) throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
    return HexFormat.of().formatHex(digest);
  }

  private void validate(Catalog value) {
    validateCatalogShape(value);
    validateRuleCount(value.rules());

    Set<String> ids = new HashSet<>();
    for (Rule rule : value.rules()) {
      validateRuleIdentity(rule, ids);
      validateRuleMetadata(rule);
    }
  }

  private void validateCatalogShape(Catalog value) {
    if (value == null
        || value.version() == null
        || value.version().isBlank()
        || value.rules() == null) {
      throw new ApiException("指纹规则缺少版本号或规则列表");
    }
  }

  private void validateRuleCount(List<Rule> rules) {
    if (rules.size() > MAX_RULES) {
      throw new ApiException("指纹规则数量超过 10000 条限制");
    }
  }

  private void validateRuleIdentity(Rule rule, Set<String> ids) {
    if (rule == null
        || rule.id() == null
        || !RULE_ID.matcher(rule.id()).matches()
        || !ids.add(rule.id())) {
      throw new ApiException("指纹规则标识无效或重复");
    }
  }

  private void validateRuleMetadata(Rule rule) {
    if (rule.name() == null
        || rule.name().isBlank()
        || rule.confidence() < 1
        || rule.confidence() > 100) {
      log.warn("指纹规则名称或置信度无效");
      throw new ApiException("指纹规则名称或置信度无效");
    }
  }

  private record LoadedCatalog(Catalog catalog, String sha256, CatalogSource source) {}

  public enum CatalogSource {
    BUILTIN,
    MANAGED,
    EXTERNAL
  }

  public record Catalog(String version, List<Rule> rules) {}

  public record Rule(
      String id,
      String name,
      String category,
      int confidence,
      Map<String, List<String>> headers,
      List<String> body,
      List<String> cookies,
      List<String> title,
      List<String> header) {}

  public record CatalogInfo(
      String version, String sha256, int ruleCount, CatalogSource source) {
    public CatalogInfo(String version, String sha256, int ruleCount) {
      this(version, sha256, ruleCount, CatalogSource.BUILTIN);
    }
  }
}
