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
 * 流/进程输出"单行无界"静态护栏——Round 19。
 *
 * <p>Round 17/18 修复了 AI SSE 与 5 个扫描器用 {@code BufferedReader.readLine()} 无单行上限
 * 导致的内存耗尽。本测试把"主源码中任何以 {@code .readLine()} 消费流的读取，都必须经由
 * {@link com.bachelor.toolbox.common.BoundedLineReader}"固化为可执行断言，防止后续新增代码
 * 再次引入"单行无限增长 → OOM"的回归。
 *
 * <p>判定：某文件若出现 {@code .readLine()}，则同文件必须出现 {@code BoundedLineReader}。
 */
@DisplayName("流读取单行有界静态护栏（Round 19）")
class BoundedStreamReadDisciplineTest {

  @Test
  @DisplayName("BSD-1 主源码中每个 .readLine() 读取点都必须使用 BoundedLineReader")
  void everyReadLineUsesBoundedReader() throws IOException {
    Path mainSrc = Path.of("src", "main", "java");
    assertThat(mainSrc).as("需在 security-toolbox-server 模块目录下运行").exists();

    List<String> violations = new ArrayList<>();
    try (Stream<Path> files = Files.walk(mainSrc)) {
      for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        if (!content.contains(".readLine(")) {
          continue;
        }
        if (!content.contains("BoundedLineReader")) {
          violations.add(file.getFileName().toString());
        }
      }
    }
    assertThat(violations)
        .as("这些文件用 .readLine() 消费流却未使用 BoundedLineReader（单行无上限可致 OOM）；"
            + "请改用 common.BoundedLineReader 为单行设上限")
        .isEmpty();
  }

  @Test
  @DisplayName("BSD-2 已知高风险读取点均使用 BoundedLineReader")
  void knownHotspotsUseBoundedReader() throws IOException {
    for (String f :
        List.of(
            "src/main/java/com/bachelor/toolbox/ai/AiAgentRuntimeClient.java",
            "src/main/java/com/bachelor/toolbox/ai/AiModelClient.java",
            "src/main/java/com/bachelor/toolbox/tool/NucleiScanTool.java",
            "src/main/java/com/bachelor/toolbox/tool/SqlmapScanTool.java",
            "src/main/java/com/bachelor/toolbox/tool/AfrogScanTool.java",
            "src/main/java/com/bachelor/toolbox/tool/XrayScanTool.java",
            "src/main/java/com/bachelor/toolbox/tool/NmapServiceScanTool.java")) {
      Path p = Path.of(f);
      if (!Files.exists(p)) continue;
      assertThat(Files.readString(p, StandardCharsets.UTF_8))
          .as(f + " 必须使用 BoundedLineReader")
          .contains("BoundedLineReader");
    }
  }
}
