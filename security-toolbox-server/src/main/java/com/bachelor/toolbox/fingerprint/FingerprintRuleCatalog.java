package com.bachelor.toolbox.fingerprint;

import com.bachelor.toolbox.common.ApiException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

@Service
public class FingerprintRuleCatalog {
  private static final Logger log = LoggerFactory.getLogger(FingerprintRuleCatalog.class);
  private static final long MAX_BYTES = 2 * 1024 * 1024;
  private static final int MAX_RULES = 10_000;
  private static final Pattern RULE_ID = Pattern.compile("[a-z0-9][a-z0-9._-]{0,79}");

  private final ObjectMapper mapper;
  private final String externalFile;
  private volatile Catalog catalog;
  private volatile String sha256;

  public FingerprintRuleCatalog(
      ObjectMapper mapper, @Value("${toolbox.fingerprints.rules-file:}") String externalFile) {
    this.mapper = mapper;
    this.externalFile = externalFile == null ? "" : externalFile.trim();
  }

  @PostConstruct
  public void load() {
    reload();
  }

  public synchronized CatalogInfo reload() {
    try {
      LoadedCatalog loaded = loadCatalog();
      catalog = loaded.catalog();
      sha256 = loaded.sha256();
      return info();
    } catch (ApiException ex) {
      log.warn("指纹规则校验失败，source={}", ruleSource(), ex);
      throw ex;
    } catch (Exception ex) {
      log.error("加载指纹规则失败，source={}", ruleSource(), ex);
      throw new ApiException("无法加载指纹规则，请检查规则文件后重试");
    }
  }

  public CatalogInfo info() {
    return new CatalogInfo(catalog.version(), sha256, catalog.rules().size());
  }

  public List<Rule> rules() {
    return catalog.rules();
  }

  private LoadedCatalog loadCatalog() throws Exception {
    byte[] bytes = readRuleBytes();
    Catalog parsed = mapper.readValue(bytes, Catalog.class);
    validate(parsed);
    Catalog immutableCatalog = new Catalog(parsed.version(), List.copyOf(parsed.rules()));
    return new LoadedCatalog(immutableCatalog, calculateSha256(bytes));
  }

  private String calculateSha256(byte[] bytes) throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
    return HexFormat.of().formatHex(digest);
  }

  private byte[] readRuleBytes() throws IOException {
    if (!externalFile.isBlank()) {
      Path file = Path.of(externalFile).toAbsolutePath().normalize();
      if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || Files.size(file) > MAX_BYTES) {
        throw new ApiException("指纹规则文件不存在或超过 2MB 限制");
      }
      return Files.readAllBytes(file);
    }

    ClassPathResource resource = new ClassPathResource("fingerprints/default-rules.json");
    try (InputStream input = resource.getInputStream()) {
      return input.readAllBytes();
    }
  }

  private String ruleSource() {
    return externalFile.isBlank() ? "classpath:fingerprints/default-rules.json" : externalFile;
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
    if (rule.id() == null || !RULE_ID.matcher(rule.id()).matches() || !ids.add(rule.id())) {
      throw new ApiException("指纹规则标识无效或重复");
    }
  }

  private void validateRuleMetadata(Rule rule) {
    if (rule.name() == null
        || rule.name().isBlank()
        || rule.confidence() < 1
        || rule.confidence() > 100) {
      log.warn("指纹规则名称或置信度无效，ruleId={}", rule.id());
      throw new ApiException("指纹规则名称或置信度无效");
    }
  }

  private record LoadedCatalog(Catalog catalog, String sha256) {}

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

  public record CatalogInfo(String version, String sha256, int ruleCount) {}
}
