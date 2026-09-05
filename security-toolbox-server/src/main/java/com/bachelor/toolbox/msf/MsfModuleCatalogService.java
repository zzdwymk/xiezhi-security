package com.bachelor.toolbox.msf;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.vulnerability.CatalogSyncProgress;
import com.bachelor.toolbox.vulnerability.ScannerPocCatalogSyncResult;
import com.bachelor.toolbox.vulnerability.VulnerabilityDefinition;
import com.bachelor.toolbox.vulnerability.VulnerabilityDefinitionRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 运行时枚举本机 MetasploitFramework 模块并入库到 {@code vulnerability_definitions}
 * （{@code SOURCE_TYPE="MSF"}，{@code source_external_id=模块路径}）。
 *
 * <p>MSF 模块是框架内嵌的 Ruby 文件，不适用「poc 文件 + sha256」的语义：这里不写入模板 hash，
 * 而以模块在框架内的唯一路径作为 {@code source_external_id}。deactivated 移除的模块仅将
 * {@code sourceActive} 置 false，不删除任何本地文件（MSF 无独立可分发模块目录）。
 */
@Service
public class MsfModuleCatalogService {
  public static final String SOURCE_TYPE = "MSF";
  private static final Logger log = LoggerFactory.getLogger(MsfModuleCatalogService.class);
  private static final int MAX_TEXT = 1_950;

  private final MsfModuleEnumerator enumerator;
  private final VulnerabilityDefinitionRepository repository;
  private final boolean syncOnStartup;
  private final AtomicBoolean syncing = new AtomicBoolean();
  private volatile ScannerPocCatalogSyncResult lastResult;
  private volatile CatalogSyncProgress progress = CatalogSyncProgress.idle(SOURCE_TYPE);

  public MsfModuleCatalogService(
      MsfModuleEnumerator enumerator,
      VulnerabilityDefinitionRepository repository,
      @org.springframework.beans.factory.annotation.Value(
              "${toolbox.vulnerability-catalog.msf.import-on-startup:false}")
          boolean syncOnStartup) {
    this.enumerator = enumerator;
    this.repository = repository;
    this.syncOnStartup = syncOnStartup;
  }

  @Async
  @EventListener(ApplicationReadyEvent.class)
  public void importOnStartup() {
    if (!syncOnStartup) return;
    try {
      sync();
    } catch (Exception ex) {
      log.error("启动时同步 Metasploit 模块失败", ex);
    }
  }

  @Transactional
  public ScannerPocCatalogSyncResult sync() {
    if (!syncing.compareAndSet(false, true)) {
      throw new ApiException("MSF 模块正在同步，请稍候");
    }
    Instant startedAt = Instant.now();
    updateProgress("RUNNING", 0, 0, "正在枚举 Metasploit 模块", startedAt, true);
    try {
      List<MsfModuleOutputParser.MsfLine> modules;
      try {
        modules = enumerator.enumerate();
      } catch (ApiException ex) {
        updateProgress("FAILED", 0, 0, "MSF 模块同步失败", startedAt, false);
        throw ex;
      } catch (Exception ex) {
        updateProgress("FAILED", 0, 0, "MSF 模块同步失败", startedAt, false);
        throw new ApiException("MSF 模块枚举失败：" + abbreviate(ex.getMessage(), 120));
      }
      updateProgress("IMPORTING", 0, modules.size(), "正在导入 MSF 模块元数据", startedAt, true);

      Map<String, VulnerabilityDefinition> existing = new HashMap<>();
      for (VulnerabilityDefinition item : repository.findAllBySourceType(SOURCE_TYPE)) {
        if (item.getSourceExternalId() != null) {
          existing.putIfAbsent(item.getSourceExternalId(), item);
        }
      }

      int imported = 0;
      int updated = 0;
      int unchanged = 0;
      int invalid = 0;
      int processed = 0;
      List<String> warnings = new ArrayList<>();
      List<VulnerabilityDefinition> pending = new ArrayList<>();
      Set<String> seen = new HashSet<>();
      for (MsfModuleOutputParser.MsfLine line : modules) {
        String id = line.modulePath();
        if (!seen.add(id)) {
          invalid++;
          continue;
        }
        try {
          VulnerabilityDefinition item = existing.get(id);
          boolean isNew = item == null;
          if (isNew) item = new VulnerabilityDefinition();
          if (isNew || changed(item, line)) {
            apply(item, line);
            pending.add(item);
            if (isNew) imported++;
            else updated++;
          } else {
            unchanged++;
          }
        } catch (Exception ex) {
          invalid++;
          if (warnings.size() < 20) warnings.add("MSF 模块解析失败，已跳过");
        } finally {
          processed++;
          if (processed == modules.size() || processed % 50 == 0) {
            updateProgress(
                "IMPORTING", processed, modules.size(), "正在导入 MSF 模块元数据", startedAt, true);
          }
        }
      }
      if (!pending.isEmpty()) repository.saveAll(pending);

      List<VulnerabilityDefinition> stale =
          existing.values().stream()
              .filter(item -> !seen.contains(item.getSourceExternalId()))
              .filter(item -> !Boolean.FALSE.equals(item.getSourceActive()))
              .toList();
      stale.forEach(item -> item.setSourceActive(false));
      if (!stale.isEmpty()) repository.saveAll(stale);

      if (modules.isEmpty()) {
        warnings.add("未从本机 Metasploit 枚举到 auxiliary/exploit 模块，请确认 Framework 已完整安装并刷新依赖");
      }
      ScannerPocCatalogSyncResult result =
          new ScannerPocCatalogSyncResult(
              "SUCCESS",
              SOURCE_TYPE,
              "framework://modules",
              "runtime",
              modules.size(),
              imported,
              updated,
              unchanged,
              invalid,
              stale.size(),
              Instant.now(),
              List.copyOf(warnings));
      lastResult = result;
      updateProgress("COMPLETED", modules.size(), modules.size(), "MSF 模块同步完成", startedAt, false);
      return result;
    } catch (RuntimeException ex) {
      updateProgress("FAILED", 0, 0, "MSF 模块同步失败", startedAt, false);
      log.error("MSF 模块同步失败", ex);
      throw ex;
    } finally {
      syncing.set(false);
    }
  }

  public boolean isSyncing() {
    return syncing.get();
  }

  public ScannerPocCatalogSyncResult lastResult() {
    return lastResult;
  }

  public CatalogSyncProgress progress() {
    return progress;
  }

  public long countActive() {
    return repository.countBySourceTypeAndEnabledTrueAndSourceActiveTrue(SOURCE_TYPE);
  }

  public boolean clearModules() {
    if (!syncing.compareAndSet(false, true)) {
      throw new ApiException("MSF 模块正在同步，请稍候");
    }
    try {
      lastResult = null;
      repository.deleteBySourceTypeInBulk(List.of(SOURCE_TYPE));
      return true;
    } finally {
      syncing.set(false);
    }
  }

  private boolean changed(VulnerabilityDefinition item, MsfModuleOutputParser.MsfLine line) {
    return !truncate(line.name(), 200).equals(item.getName())
        || !severity(line.category(), line.rank()).equals(item.getSeverity())
        || !category(line).equals(item.getCategory())
        || !line.modulePath().equals(item.getTemplateRelativePath())
        || !Boolean.TRUE.equals(item.getSourceActive());
  }

  private void apply(VulnerabilityDefinition item, MsfModuleOutputParser.MsfLine line) {
    if (item.getId() == null) {
      item.setVulnerabilityCode(stableCodeFor(line.modulePath()));
      item.setEnabled(true);
      item.setImportedAt(Instant.now());
      item.setSourceVersion("runtime");
    }
    item.setName(truncate(line.name(), 200));
    item.setSeverity(severity(line.category(), line.rank()));
    item.setCategory(category(line));
    item.setDescription(truncate(orMissing(line.description()), MAX_TEXT));
    item.setDetectionGuidance(truncate(detectionGuidance(line.category()), MAX_TEXT));
    item.setRemediation(
        "依据 MSF 模块说明与厂商公告确认影响，完成升级、补丁、配置加固或访问控制后复测。");
    item.setReferenceUrls(truncate("https://www.metasploit.com/", MAX_TEXT));
    item.setSourceType(SOURCE_TYPE);
    item.setSourceName("MetasploitFramework");
    item.setSourceExternalId(truncate(line.modulePath(), 255));
    item.setSourceUrl(truncate(msfSearchUrl(line.modulePath()), 1200));
    item.setTemplateRelativePath(truncate(line.modulePath(), 1000));
    item.setTemplateSha256(null);
    item.setTemplateSigned(false);
    item.setProtocols("");
    item.setAuthors("MetasploitFramework");
    item.setTags(truncate(line.category() + "," + line.rank(), 2000));
    item.setCveIds("");
    item.setCweIds("");
    item.setVerificationStatus("LOCAL_UNVERIFIED");
    item.setScanSafety(scanSafety(line));
    item.setRequiresInteractsh(false);
    item.setSourceActive(true);
    item.setSourceUpdatedAt(Instant.now());
  }

  private String category(MsfModuleOutputParser.MsfLine line) {
    String path = line.modulePath().toLowerCase(Locale.ROOT);
    if (path.contains("/scanner/") || path.contains("/probe/")) return "MSF 辅助探测";
    if (path.contains("/dos/")) return "拒绝服务";
    if (line.category().equalsIgnoreCase("exploit")) return "MSF 利用模块";
    return "MSF 辅助模块";
  }

  private String severity(String category, String rank) {
    String r = rank.toLowerCase(Locale.ROOT);
    if ("exploit".equalsIgnoreCase(category)) {
      return switch (r) {
        case "excellent", "great" -> "CRITICAL";
        case "good", "average" -> "HIGH";
        case "normal" -> "MEDIUM";
        default -> "LOW";
      };
    }
    return "INFO";
  }

  private String scanSafety(MsfModuleOutputParser.MsfLine line) {
    if ("exploit".equalsIgnoreCase(line.category())) {
      return "REVIEW_REQUIRED";
    }
    if (line.modulePath().toLowerCase(Locale.ROOT).contains("/scanner/")) {
      return "SAFE";
    }
    return "REVIEW_REQUIRED";
  }

  private String detectionGuidance(String category) {
    if ("exploit".equalsIgnoreCase(category)) {
      return "exploit 模块仅作受控验证；默认不反弹会话，请人工确认影响与利用条件后复测。";
    }
    return "auxiliary 模块为框架内置辅助探测；在确认模块行为后可在授权范围内执行。";
  }

  public static String stableCodeFor(String modulePath) {
    try {
      byte[] digest =
          java.security.MessageDigest.getInstance("SHA-256")
              .digest(("MSF\0" + modulePath).getBytes(java.nio.charset.StandardCharsets.UTF_8));
      return "MSF-" + java.util.HexFormat.of().formatHex(digest, 0, 12).toUpperCase(Locale.ROOT);
    } catch (Exception ex) {
      throw new IllegalStateException("无法生成 MSF 模块稳定编号", ex);
    }
  }

  private String msfSearchUrl(String modulePath) {
    return "https://intl.exploit-db.com/?search=" + forUri(modulePath);
  }

  private String forUri(String value) {
    try {
      return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
    } catch (Exception ignore) {
      return "msf";
    }
  }

  private void updateProgress(
      String stage, long processed, long total, String message, Instant startedAt, boolean active) {
    progress =
        new CatalogSyncProgress(
            SOURCE_TYPE,
            stage,
            Math.max(0, processed),
            Math.max(0, total),
            message,
            startedAt,
            Instant.now(),
            active);
  }

  private String orMissing(String value) {
    return value == null || value.isBlank() ? "Metasploit 模块官方未提供描述。" : value;
  }

  private String truncate(String value, int max) {
    if (value == null) return null;
    String clean = value.trim();
    return clean.length() <= max ? clean : clean.substring(0, max - 1) + "…";
  }

  private String abbreviate(String value, int max) {
    String clean = value == null ? "" : value.replaceAll("\\s+", " ").trim();
    return clean.length() <= max ? clean : clean.substring(0, max) + "…";
  }
}