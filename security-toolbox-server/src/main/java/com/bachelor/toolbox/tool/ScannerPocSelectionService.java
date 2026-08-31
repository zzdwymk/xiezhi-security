package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.vulnerability.HostPluginCatalogService;
import com.bachelor.toolbox.vulnerability.NucleiTemplateCatalogService;
import com.bachelor.toolbox.vulnerability.ScannerPocCatalogService;
import com.bachelor.toolbox.vulnerability.VulnerabilityDefinition;
import com.bachelor.toolbox.vulnerability.VulnerabilityDefinitionRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class ScannerPocSelectionService {
  public static final String PARAMETER = "pocCodes";
  public static final String ALL_PARAMETER = "allPocs";
  public static final String SAFE_ONLY_PARAMETER = "scheduledSafeOnly";
  private static final int MAX_SELECTED_POCS = 50;

  private final VulnerabilityDefinitionRepository repository;
  private final ObjectMapper objectMapper;
  private final Map<String, Path> roots;

  public ScannerPocSelectionService(
      VulnerabilityDefinitionRepository repository,
      ObjectMapper objectMapper,
      @Value("${toolbox.execution.nuclei-templates-path:${user.home}/nuclei-templates}")
          String nucleiPath,
      @Value("${toolbox.execution.afrog-pocs-path:${user.home}/afrog-pocs}")
          String afrogPath,
      @Value("${toolbox.execution.xray-pocs-path:${user.home}/xray-pocs}") String xrayPath,
      @Value("${toolbox.vulnerability-catalog.host.plugins-path:${user.home}/host-plugins}")
          String hostPluginsPath) {
    this.repository = repository;
    this.objectMapper = objectMapper;
    this.roots =
        Map.of(
            NucleiTemplateCatalogService.SOURCE_TYPE,
            Path.of(nucleiPath).toAbsolutePath().normalize(),
            ScannerPocCatalogService.AFROG,
            Path.of(afrogPath).toAbsolutePath().normalize(),
            ScannerPocCatalogService.XRAY,
            Path.of(xrayPath).toAbsolutePath().normalize(),
            HostPluginCatalogService.SOURCE_TYPE,
            Path.of(hostPluginsPath).toAbsolutePath().normalize());
  }

  public List<SelectedPoc> resolve(
      String requestedSource, Map<String, Object> parameters, boolean allowEmpty) {
    String source = normalizeSource(requestedSource);
    Map<String, Object> safeParameters = parameters == null ? Map.of() : parameters;
    if (!Set.of(PARAMETER, ALL_PARAMETER, SAFE_ONLY_PARAMETER)
        .containsAll(safeParameters.keySet())) {
      throw new ApiException(source + " 扫描包含未允许的参数");
    }
    boolean safeOnly = selectsSafeOnly(safeParameters);
    boolean all = selectsAll(safeParameters);
    List<String> requested = pocCodes(safeParameters.get(PARAMETER));
    List<VulnerabilityDefinition> selectedDefinitions = List.of();
    if (all && !requested.isEmpty()) {
      throw new ApiException(source + " 不能同时选择全部 PoC 和具体 PoC");
    }
    if (all) {
      selectedDefinitions =
          repository.findAllBySourceTypeAndEnabledTrueAndSourceActiveTrue(source);
      requested = selectedDefinitions.stream().map(VulnerabilityDefinition::getVulnerabilityCode).toList();
      if (requested.isEmpty()) throw new ApiException("未同步到可执行的 " + source + " PoC");
    }
    if (requested.isEmpty()) {
      if (allowEmpty) return List.of();
      throw new ApiException("请至少选择一个 " + source + " PoC");
    }
    if (!all && requested.size() > MAX_SELECTED_POCS) {
      throw new ApiException("单次扫描最多选择 " + MAX_SELECTED_POCS + " 个 PoC");
    }
    if (new LinkedHashSet<>(requested).size() != requested.size()) {
      throw new ApiException("PoC 不能重复选择");
    }

    Map<String, VulnerabilityDefinition> definitions = new LinkedHashMap<>();
    (all ? selectedDefinitions : repository.findAllByVulnerabilityCodeIn(requested))
        .forEach(item -> definitions.put(item.getVulnerabilityCode(), item));
    if (definitions.size() != requested.size()) throw new ApiException("请求包含不存在的 PoC");
    Path root = roots.get(source);
    List<SelectedPoc> result = new ArrayList<>(requested.size());
    for (String code : requested) {
      VulnerabilityDefinition item = definitions.get(code);
      if (!source.equals(item.getSourceType())
          || !item.isEnabled()
          || !Boolean.TRUE.equals(item.getSourceActive())) {
        throw new ApiException("PoC " + code + " 不允许由 " + source + " 自动执行");
      }
      if (safeOnly && !"SAFE".equalsIgnoreCase(item.getScanSafety())) {
        throw new ApiException("定时扫描仅允许执行标记为 SAFE 的 PoC: " + code);
      }
      String relative = item.getTemplateRelativePath();
      String expectedHash = item.getTemplateSha256();
      if (relative == null
          || relative.isBlank()
          || expectedHash == null
          || !expectedHash.matches("(?i)[a-f0-9]{64}")) {
        throw new ApiException("PoC " + code + " 缺少可核验的本地文件信息");
      }
      Path file = root.resolve(relative).normalize();
      if (!file.startsWith(root)
          || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
          || !sha256(file).equalsIgnoreCase(expectedHash)) {
        throw new ApiException("PoC " + code + " 文件已变化，请重新同步漏洞库");
      }
      result.add(
          new SelectedPoc(
              code,
              item.getSourceExternalId(),
              item.getName(),
              item.getSeverity(),
              file,
              expectedHash.toLowerCase(Locale.ROOT)));
    }
    return List.copyOf(result);
  }

  public boolean selectsAll(Map<String, Object> parameters) {
    if (parameters == null) return false;
    Object value = parameters.get(ALL_PARAMETER);
    if (value == null) return false;
    if (!(value instanceof Boolean selected)) throw new ApiException("全部 PoC 参数格式无效");
    return selected;
  }

  public boolean selectsSafeOnly(Map<String, Object> parameters) {
    if (parameters == null) return false;
    Object value = parameters.get(SAFE_ONLY_PARAMETER);
    if (value == null) return false;
    if (!(value instanceof Boolean selected)) throw new ApiException("定时安全参数格式无效");
    return selected;
  }

  public String selectionHash(String toolCode, String requestJson) throws Exception {
    String source = sourceForTool(toolCode);
    if (source == null) return null;
    Map<String, Object> parameters =
        requestJson == null || requestJson.isBlank()
            ? Map.of()
            : objectMapper.readValue(requestJson, new TypeReference<Map<String, Object>>() {});
    List<SelectedPoc> selected = resolve(source, parameters, "nuclei_scan".equals(toolCode));
    if (selected.isEmpty()) return null;
    String manifest =
        selected.stream()
            .sorted(Comparator.comparing(SelectedPoc::vulnerabilityCode))
            .map(item -> item.vulnerabilityCode() + "\0" + item.sha256())
            .reduce((left, right) -> left + "\n" + right)
            .orElse("");
    return sha256(manifest.getBytes(StandardCharsets.UTF_8));
  }

  public static String sourceForTool(String toolCode) {
    return switch (toolCode) {
      case "nuclei_scan" -> NucleiTemplateCatalogService.SOURCE_TYPE;
      case "afrog_scan" -> ScannerPocCatalogService.AFROG;
      case "xray_scan" -> ScannerPocCatalogService.XRAY;
      case "native_vuln_scan" -> HostPluginCatalogService.SOURCE_TYPE;
      default -> null;
    };
  }

  private List<String> pocCodes(Object value) {
    if (value == null) return List.of();
    if (!(value instanceof Collection<?> collection)) throw new ApiException("PoC 参数格式无效");
    List<String> result = new ArrayList<>();
    for (Object item : collection) {
      String code = String.valueOf(item).trim();
      if (!code.matches("[A-Z]{2}-[A-F0-9]{24}")) throw new ApiException("PoC 编号格式无效");
      result.add(code);
    }
    return List.copyOf(result);
  }

  private String normalizeSource(String value) {
    String source = value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    if (!roots.containsKey(source)) throw new ApiException("扫描器 PoC 来源不受支持");
    return source;
  }

  private String sha256(Path file) {
    try {
      return sha256(Files.readAllBytes(file));
    } catch (Exception ex) {
      throw new ApiException("无法校验 PoC 文件");
    }
  }

  private String sha256(byte[] value) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
  }

  public record SelectedPoc(
      String vulnerabilityCode,
      String externalId,
      String name,
      String severity,
      Path file,
      String sha256) {}
}
