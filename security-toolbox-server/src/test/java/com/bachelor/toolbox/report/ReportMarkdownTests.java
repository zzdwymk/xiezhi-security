package com.bachelor.toolbox.report;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.junit.jupiter.api.Test;

class ReportMarkdownTests {
  @Test
  void rendersGfmStructureAndSoftBreaks() {
    Document document = render("""
        ## 研判结论

        **高风险**，*应复核*，~~旧结论~~。
        第二行

        - 检查证据
        - 安排整改

        3. 复测

        > 证据存在局限

        | 风险 | 优先级 |
        | --- | --- |
        | 示例 | 高 |
        """);

    assertThat(document.select("h2").text()).isEqualTo("研判结论");
    assertThat(document.select("strong").text()).isEqualTo("高风险");
    assertThat(document.select("em").text()).isEqualTo("应复核");
    assertThat(document.select("del").text()).isEqualTo("旧结论");
    assertThat(document.select("p br")).hasSize(1);
    assertThat(document.select("ul > li")).hasSize(2);
    assertThat(document.select("ol").attr("start")).isEqualTo("3");
    assertThat(document.select("blockquote").text()).isEqualTo("证据存在局限");
    assertThat(document.select("table thead th").eachText()).containsExactly("风险", "优先级");
    assertThat(document.select("table tbody td").eachText()).containsExactly("示例", "高");
  }

  @Test
  void keepsCodeAsEscapedText() {
    Document document = render("""
        `x < y && y > 0`

        ```html
        <script>alert('test')</script>
        <img src="https://example.com/image.png" onerror="alert(1)">
        ```
        """);

    assertThat(document.select("code")).hasSize(2);
    assertThat(document.select("p code").text()).isEqualTo("x < y && y > 0");
    assertThat(document.select("pre code").text())
        .contains("<script>alert('test')</script>", "<img src=");
    assertThat(document.select("script, img")).isEmpty();
  }

  @Test
  void removesActiveHtmlMediaAndAttributes() {
    Document document = render("""
        <script>alert('script')</script>
        <style>body{display:none}</style>
        <iframe srcdoc="<script>alert(1)</script>"></iframe>
        <object data="https://example.com"></object>
        <embed src="https://example.com">
        <form action="https://example.com"><input name="secret"><button>提交</button></form>
        <img src="https://example.com/pixel.png" onerror="alert(1)">
        <video src="https://example.com/video"><source src="https://example.com/other"></video>
        <audio src="https://example.com/audio"></audio>
        <svg onload="alert(1)"><a href="javascript:alert(1)">svg</a></svg>
        <h2 style="display:none" onclick="alert(1)" id="outside">安全标题</h2>

        ![remote](https://example.com/remote.png)
        """);

    assertThat(document.select("script, style, iframe, object, embed, form, input, button, img, video, audio, source, svg"))
        .isEmpty();
    assertThat(document.select("h2").text()).isEqualTo("安全标题");
    assertThat(document.select("h2").first().attributes().size()).isZero();
    assertThat(document.body().html()).doesNotContain("alert(", "display:none", "https://example.com/pixel.png");
  }

  @Test
  void allowsOnlyHttpAndFragmentLinksWithSafeExternalAttributes() {
    Document document = render("""
        [HTTPS](https://example.com/evidence?x=1&y=2 "证据")
        [HTTP](http://example.com)
        [fragment](#evidence)
        [relative](/settings)
        [protocol-relative](//example.com)
        [file](file:///C:/private)
        [data](data:text/html,test)
        [mail](mailto:user@example.com)
        <a href="javascript:alert(1)">javascript</a>
        <a href="jav&#x61;script:alert(1)">encoded</a>
        <a href="java&#x09;script:alert(1)">whitespace</a>
        <a href="https://example.com" target="opener" rel="opener" onclick="alert(1)">raw</a>
        """);

    assertThat(document.select("a[href]")).hasSize(4);
    assertThat(document.select("a[href^=http]")).hasSize(3).allSatisfy(anchor -> {
      assertThat(anchor.attr("target")).isEqualTo("_blank");
      assertThat(anchor.attr("rel")).isEqualTo("noopener noreferrer");
      assertThat(anchor.hasAttr("onclick")).isFalse();
    });
    assertThat(document.select("a[href='#evidence']").attr("target")).isEmpty();
    assertThat(document.select("a").first().attr("title")).isEqualTo("证据");
    assertThat(document.select("a").eachText()).contains("relative", "file", "javascript", "encoded", "whitespace");
  }

  @Test
  void malformedNestedHtmlCannotEscapeTheReportContainer() {
    Document document = render("""
        </div></main><html><head><base href="https://example.com"><meta http-equiv="refresh" content="0;url=https://example.com"></head>
        <body><p><a href="javascript:alert(1)"><strong>保留文本</a></strong></p>
        <math><mtext><table><mglyph><style><!--</style><img title="--><img src=x onerror=alert(1)>">
        """);

    assertThat(document.select("base, meta, script, style, img, math, main, div")).isEmpty();
    assertThat(document.select("a[href]")).isEmpty();
    assertThat(document.body().text()).contains("保留文本");
  }

  @Test
  void handlesAbsentAndPlainTextSummaries() {
    assertThat(ReportMarkdown.render(null)).isEmpty();
    assertThat(render("AI 综合研判暂不可用。").select("p").text()).isEqualTo("AI 综合研判暂不可用。");
  }

  @Test
  void localizesKnownToolNamesAndUppercaseStatesInRenderedProse() {
    Document document = render("""
        ## 状态：RUNNING

        **nmap_service_scan**：SUCCESS。PENDING、FAILED、TIMEOUT、CANCELLED。
        APPROVED、REJECTED、CONFIRMED、NOT_REQUIRED、QUEUED、COMPLETED、SKIPPED、STOPPED、WAITING_TASKS。
        BLOCKED、DRAFT、DISPATCHED、EXPIRED、OPEN、FALSE_POSITIVE、FIXED、REOPENED。

        | 工具 |
        | --- |
        | retrieve_project_context |
        | tcp_ports |
        | http_headers |
        | http_security_check |
        | tls_config |
        | nuclei_scan |
        | afrog_scan |
        | xray_scan |
        | zap_scan |
        | zap_fuzz |
        | sqlmap_scan |
        | fscan_scan |
        | msf_scan |
        """);

    assertThat(document.select("h2").text()).isEqualTo("状态：执行中");
    assertThat(document.select("strong").text()).isEqualTo("Nmap 服务识别");
    assertThat(document.select("p").text()).contains(
        "已完成。待处理、失败、超时、已取消。",
        "已通过、已拒绝、已确认、无需确认、排队中、已完成、已跳过、已停止、等待前置任务。",
        "受阻、草稿、已下发、已过期、待确认、误报、已修复、已复现。");
    assertThat(document.select("tbody td").eachText()).containsExactly(
        "项目上下文检索", "TCP 端口探测", "HTTP 安全响应头检查", "HTTP 常见安全检查",
        "TLS 基础配置检查", "Nuclei 通用漏洞扫描", "Afrog 漏洞扫描", "Xray 漏洞扫描",
        "OWASP ZAP 主动扫描", "ZAP 单次参数变异验证", "sqlmap SQL 注入检测", "fscan 主机扫描",
        "Metasploit 模块执行");
  }

  @Test
  void localizesOnlyWholeKnownInlineValuesAndPreservesExecutableCode() {
    Document document = render("""
        `tcp_ports`、`RUNNING`、`NOT_REQUIRED`

        `curl -H 'X-Status: RUNNING' https://example.com/tcp_ports`
        `echo SUCCESS`、`status=FAILED`、`RUNNING SUCCESS`、`Turn`、`unknown_tool`

        ```sh
        tcp_ports
        echo SUCCESS
        curl https://example.com/RUNNING
        ```

        <pre>FAILED <code>tcp_ports</code></pre>
        <kbd>RUNNING</kbd> <samp>SUCCESS <code>tcp_ports</code></samp>
        """);

    assertThat(document.select("p > code").eachText()).containsExactly(
        "TCP 端口探测", "执行中", "无需确认",
        "curl -H 'X-Status: RUNNING' https://example.com/tcp_ports",
        "echo SUCCESS", "status=FAILED", "RUNNING SUCCESS", "Turn", "unknown_tool");
    assertThat(document.select("pre code").first().wholeText())
        .isEqualTo("tcp_ports\necho SUCCESS\ncurl https://example.com/RUNNING\n");
    assertThat(document.select("pre").last().text()).isEqualTo("FAILED tcp_ports");
    assertThat(document.select("kbd").text()).isEqualTo("RUNNING");
    assertThat(document.select("samp").text()).isEqualTo("SUCCESS tcp_ports");
  }

  @Test
  void preservesLinksUrlsPathsAndUnknownIdentifiers() {
    Document document = render("""
        [tcp_ports](https://example.com/tcp_ports?state=RUNNING,SUCCESS "RUNNING tcp_ports")
        [https://example.com/SUCCESS](https://example.com/SUCCESS)
        [RUNNING](#RUNNING)

        https://example.com/tcp_ports?state=RUNNING,SUCCESS
        www.example.com/tcp_ports?state=FAILED
        file:///C:/RUNNING/tcp_ports
        RUNNING@example.com
        /var/tcp_ports/RUNNING C:\\RUNNING\\tcp_ports
        tcp_ports.json prefix_tcp_ports RUNNING_MODE tcp_ports-extra $SUCCESS status=FAILED
        running success UnknownTool xTurnId UNKNOWN_STATE
        """);

    assertThat(document.select("a").eachText()).containsExactly(
        "TCP 端口探测", "https://example.com/SUCCESS", "执行中");
    assertThat(document.select("a").eachAttr("href")).containsExactly(
        "https://example.com/tcp_ports?state=RUNNING,SUCCESS",
        "https://example.com/SUCCESS", "#RUNNING");
    assertThat(document.select("a").first().attr("title")).isEqualTo("执行中 TCP 端口探测");
    assertThat(document.select("p").last().wholeText()).contains(
        "https://example.com/tcp_ports?state=RUNNING,SUCCESS",
        "www.example.com/tcp_ports?state=FAILED", "file:///C:/RUNNING/tcp_ports",
        "RUNNING@example.com", "/var/tcp_ports/RUNNING C:\\RUNNING\\tcp_ports",
        "tcp_ports.json prefix_tcp_ports RUNNING_MODE tcp_ports-extra $SUCCESS status=FAILED",
        "running success UnknownTool xTurnId UNKNOWN_STATE");
  }

  @Test
  void localizesInternalTerminologyOnlyInKnownContexts() {
    Document document = render("""
        AI Runtime 返回内容未通过 Harness 协议校验。
        Ledger 摘要链已保存；Turn ID 已记录。

        Turn left. Harness the available resources. Ledger is a product name.
        HarnessCustom LedgerEntry CrossTurnRecovery AI RuntimeClient
        `AI Runtime`、`Harness 协议校验`、`Ledger 摘要链`、`Turn ID`
        """);

    assertThat(document.select("p").first().text()).isEqualTo(
        "智能服务 返回内容未通过 执行校验 协议校验。 执行记录 摘要链已保存；对话轮次 ID 已记录。");
    assertThat(document.select("p").last().text()).contains(
        "Turn left. Harness the available resources. Ledger is a product name.",
        "HarnessCustom LedgerEntry CrossTurnRecovery AI RuntimeClient");
    assertThat(document.select("code").eachText()).containsExactly(
        "AI Runtime", "Harness 协议校验", "Ledger 摘要链", "Turn ID");
  }

  @Test
  void replacesExactInternalEvidenceIdsWithoutChangingBusinessIdsCodeOrUrls() {
    String evidenceId = "ev-435b6db24330fb59cd361bf6";
    String otherEvidenceId = "ev-45d913ea223f9ff9190d4357";
    Document document = render("""
        证据ev-435b6db24330fb59cd361bf6 支持发现 #243 和任务 #435，关联 CVE-2025-12345（证据 ev-45d913ea223f9ff9190d4357）。

        `ev-435b6db24330fb59cd361bf6`、`echo ev-435b6db24330fb59cd361bf6`

        ```text
        ev-435b6db24330fb59cd361bf6
        ```

        [证据ev-435b6db24330fb59cd361bf6](https://example.test/ev-435b6db24330fb59cd361bf6 "证据 ev-45d913ea223f9ff9190d4357")
        <https://example.test/ev-45d913ea223f9ff9190d4357>
        """);

    assertThat(document.select("p").first().text()).isEqualTo(
        "相关证据 支持发现 #243 和任务 #435，关联 CVE-2025-12345（相关证据）。");
    assertThat(document.select("p > code").eachText()).containsExactly("相关证据", "echo " + evidenceId);
    assertThat(document.select("pre code").text()).isEqualTo(evidenceId);
    assertThat(document.select("a").eachAttr("href")).containsExactly(
        "https://example.test/" + evidenceId, "https://example.test/" + otherEvidenceId);
    assertThat(document.select("a").eachText()).containsExactly("相关证据", "https://example.test/" + otherEvidenceId);
    assertThat(document.select("a").first().attr("title")).isEqualTo("相关证据");
  }

  @Test
  void preservesEvidenceLookalikesCompoundIdentifiersAndPaths() {
    String evidenceId = "ev-435b6db24330fb59cd361bf6";
    List<String> originals = List.of(
        "prefix_" + evidenceId, evidenceId + "-copy", evidenceId + ".json",
        evidenceId.substring(0, evidenceId.length() - 1), evidenceId + "a", evidenceId.toUpperCase(),
        "https://example.test/" + evidenceId + "?ref=" + evidenceId,
        "/tmp/" + evidenceId, "C:\\evidence\\" + evidenceId);
    for (String original : originals) {
      assertThat(render(original).body().text()).isEqualTo(original);
    }
  }

  private Document render(String markdown) {
    return Jsoup.parseBodyFragment(ReportMarkdown.render(markdown));
  }
}
