package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.BufferedReader;
import java.io.StringReader;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 扫描器输出读取——Round 18。
 *
 * <p>各扫描器读进程 stdout 改用 BoundedLineReader：单行设 64MB 反 OOM 兜底（真正病理级超长行才中止），
 * 而 2MB 的“累计输出”上限保持不变。这样既堵住“单个无换行超长行在读入前就 OOM”的内存耗尽面，
 * 又不误伤会吐出大体积（base64 body 等）但最终被丢弃的合法大行。
 *
 * <p>真正的“单行超上限即抛异常”机制由 {@code BoundedLineReaderTest} 覆盖；本类锁定 afrog 读取行为不回归。
 */
@DisplayName("扫描器输出读取（Round 18）")
class ScannerOutputLineBoundTests {
  private final AfrogScanTool tool =
      new AfrogScanTool(
          new com.bachelor.toolbox.target.TargetPolicyService(
              false, new com.bachelor.toolbox.target.PortRangeParser()),
          new com.fasterxml.jackson.databind.ObjectMapper(),
          null,
          "afrog",
          900);

  @Test
  @DisplayName("SCAN-LINE-1 3MB 无关大行（base64 body 类）→ 正常忽略，不崩溃/不报错（< 64MB 兜底）")
  void largeDiscardedLineTolerated() throws Exception {
    String huge = "large body ".repeat(300_000); // ~3MB 单行、无换行
    BufferedReader reader = new BufferedReader(new StringReader(huge + "\nscan completed\n"));
    String out = tool.readExecutionEvidence(reader);
    assertThat(out).isNotNull();
  }

  @Test
  @DisplayName("SCAN-LINE-2 正常多行输出 → 正常返回")
  void normalOutputPasses() throws Exception {
    BufferedReader reader = new BufferedReader(new StringReader("scan started\nscan completed\n"));
    String out = tool.readExecutionEvidence(reader);
    assertThat(out).isNotNull();
  }
}
