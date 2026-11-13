package com.bachelor.toolbox.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * SSRF-经重定向"静态护栏"回归——Round 13。
 *
 * <p>Round 12 修复了 recon/probe 的 {@code Redirect.NORMAL}（会真实跟随跨主机/跨端口重定向 → SSRF）。
 * 本测试把"任何对<strong>授权目标</strong>发起请求的 {@code HttpClient} 都不应使用 {@code Redirect.NORMAL}，
 * 且必须显式声明重定向策略"固化为可执行断言，防止后续新增代码再次引入同类缺陷。
 *
 * <p>允许白名单：仅 {@code NucleiTemplateCatalogService}（固定 https://www.cisa.gov，且请求前后都校验 host）
 * 可保留 {@code Redirect.NORMAL}。
 */
@DisplayName("SSRF-重定向静态护栏（Round 13）")
class HttpClientRedirectDisciplineTest {

  /** 允许使用 Redirect.NORMAL 的源文件（固定外部官方源 + 前后 host 校验）。 */
  private static final List<String> REDIRECT_NORMAL_ALLOWLIST =
      List.of("NucleiTemplateCatalogService.java");

  @Test
  @DisplayName("SRD-1 主源码中不得存在未白名单的 Redirect.NORMAL")
  void noUnexpectedNormalRedirectInMainSources() throws IOException {
    Path mainSrc = Path.of("src", "main", "java");
    assertThat(mainSrc).as("测试需在 security-toolbox-server 模块目录下运行").exists();

    List<String> violations = new ArrayList<>();
    try (Stream<Path> files = Files.walk(mainSrc)) {
      for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        // 只匹配真实调用，不匹配注释/文档里提到的 "Redirect.NORMAL" 字样。
        if (!content.contains(".followRedirects(HttpClient.Redirect.NORMAL)")
            && !content.contains(".followRedirects(Redirect.NORMAL)")) {
          continue;
        }
        String name = file.getFileName().toString();
        if (REDIRECT_NORMAL_ALLOWLIST.contains(name)) {
          continue;
        }
        violations.add(name);
      }
    }
    assertThat(violations)
        .as("这些文件使用了 Redirect.NORMAL（会真实跟随跨主机重定向，构成 SSRF 面）；"
            + "请改用 Redirect.NEVER，或对同源 Location 手工跟随并校验 host+端口。"
            + "确属固定官方源可加入白名单")
        .isEmpty();
  }

  @Test
  @DisplayName("SRD-2 已知对授权目标发起请求的客户端均为 Redirect.NEVER")
  void targetReachingClientsAlwaysNeverRedirect() throws IOException {
    // 至少确保 Round 12 修复的两处保持 NEVER。
    for (String file :
        List.of(
            "src/main/java/com/bachelor/toolbox/probe/ProbeService.java",
            "src/main/java/com/bachelor/toolbox/recon/ReconService.java",
            "src/main/java/com/bachelor/toolbox/ai/SemanticJudgeClient.java")) {
      Path p = Path.of(file);
      if (!Files.exists(p)) continue;
      String content = Files.readString(p, StandardCharsets.UTF_8);
      assertThat(content)
          .as(file + " 必须包含 followRedirects(HttpClient.Redirect.NEVER)")
          .contains(".followRedirects(HttpClient.Redirect.NEVER)");
      assertThat(content)
          .as(file + " 不应再含真实的 .followRedirects(HttpClient.Redirect.NORMAL) 调用")
          .doesNotContain(".followRedirects(HttpClient.Redirect.NORMAL)");
    }
  }
}
