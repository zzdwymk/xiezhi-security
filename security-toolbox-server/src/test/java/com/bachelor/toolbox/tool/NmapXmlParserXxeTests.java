package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import java.time.Duration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * XXE 反序列化面回归（第396轮）。
 *
 * <p>{@link NmapXmlParser} 是服务端**唯一**的 XML 解析点（解析 nmap 自身的 XML 输出）。
 * 该解析器已做加固：禁用 DOCTYPE、外部通用/参数实体、外部 DTD、XInclude，并把
 * {@code ACCESS_EXTERNAL_DTD}/{@code ACCESS_EXTERNAL_SCHEMA} 置空。
 *
 * <p>既有测试只覆盖"带外部实体的 DOCTYPE 被拒绝"这一种写法，本类补齐其余
 * <strong>经典 XXE / XML 炸弹</strong>写法，防止将来重构（该文件有自定义的 DOCTYPE 预处理逻辑，
 * 极易被"顺手放宽")时静默退化。
 */
@DisplayName("Nmap XML 解析器的 XXE 与 XML 炸弹拒绝面（第396轮）")
class NmapXmlParserXxeTests {
  private final NmapXmlParser parser = new NmapXmlParser();

  private static final String VALID_WITH_HOST =
      "<?xml version=\"1.0\"?><!DOCTYPE nmaprun><nmaprun><host>"
          + "<status state=\"up\" reason=\"syn-ack\"/>"
          + "<address addr=\"192.168.222.155\" addrtype=\"ipv4\"/>"
          + "<ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/>"
          + "<service name=\"http\"/></port></ports>"
          + "</host></nmaprun>";

  @Test
  @DisplayName("正常 nmap 输出（含官方 DOCTYPE）仍可解析——加固不得误伤功能")
  void standardNmapOutputStillParses() {
    NmapXmlParser.NmapParseResult result = parser.parse(VALID_WITH_HOST);
    assertThat(result.openPorts()).hasSize(1);
    assertThat(result.openPorts().get(0)).containsEntry("port", 80);
    assertThat(result.hostStatuses()).isNotEmpty();
  }

  @Test
  @DisplayName("外部通用实体（读取本地文件）被拒绝")
  void externalGeneralEntityIsRejected() {
    String xml =
        "<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]>"
            + "<nmaprun><host><status state=\"&xxe;\"/></host></nmaprun>";
    assertThatThrownBy(() -> parser.parse(xml))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("实体");
  }

  @Test
  @DisplayName("外部参数实体被拒绝")
  void externalParameterEntityIsRejected() {
    String xml =
        "<!DOCTYPE nmaprun [<!ENTITY % p SYSTEM \"http://127.0.0.1:1/x.dtd\"> %p;]>"
            + "<nmaprun><host/></nmaprun>";
    assertThatThrownBy(() -> parser.parse(xml)).isInstanceOf(ApiException.class);
  }

  @Test
  @DisplayName("外部 DTD 引用被拒绝（SSRF 面）")
  void externalDtdIsRejected() {
    String xml = "<!DOCTYPE nmaprun SYSTEM \"http://127.0.0.1:1/nmap.dtd\"><nmaprun><host/></nmaprun>";
    assertThatThrownBy(() -> parser.parse(xml)).isInstanceOf(ApiException.class);
  }

  @Test
  @DisplayName("Billion Laughs（实体递归膨胀）被拒绝且不耗时")
  void billionLaughsIsRejectedQuickly() {
    StringBuilder xml = new StringBuilder("<!DOCTYPE nmaprun [");
    xml.append("<!ENTITY a0 \"lol\">");
    for (int i = 1; i <= 9; i++) {
      xml.append("<!ENTITY a").append(i).append(" \"");
      for (int j = 0; j < 10; j++) xml.append("&a").append(i - 1).append(";");
      xml.append("\">");
    }
    xml.append("]><nmaprun><host><status state=\"&a9;\"/></host></nmaprun>");

    long start = System.nanoTime();
    assertThatThrownBy(() -> parser.parse(xml.toString())).isInstanceOf(ApiException.class);
    assertThat(Duration.ofNanos(System.nanoTime() - start))
        .as("实体膨胀必须在解析阶段被拒绝，不得消耗大量 CPU/内存")
        .isLessThan(Duration.ofSeconds(3));
  }

  @Test
  @DisplayName("XInclude 不会被展开成外部内容")
  void xincludeIsNotExpanded() {
    String xml =
        "<nmaprun xmlns:xi=\"http://www.w3.org/2001/XInclude\">"
            + "<host><status state=\"up\"/><xi:include href=\"file:///c:/windows/win.ini\"/></host>"
            + "</nmaprun>";
    // 既不抛错（不是实体），也绝不能把外部文件内容读进结果：解析结果里不应出现任何 win.ini 片段。
    assertThatCode(() -> parser.parse(xml)).doesNotThrowAnyException();
    NmapXmlParser.NmapParseResult result = parser.parse(xml);
    assertThat(result.openPorts()).isEmpty();
    assertThat(result.portStates()).isEmpty();
    assertThat(result.hostStatuses()).hasSize(1);
    assertThat(String.valueOf(result.hostStatuses())).doesNotContain("[fonts]", "for 16-bit app support");
  }

  @Test
  @DisplayName("非 nmap 的任意 DOCTYPE 被拒绝")
  void foreignDoctypeIsRejected() {
    String xml = "<!DOCTYPE note><nmaprun><host/></nmaprun>";
    assertThatThrownBy(() -> parser.parse(xml)).isInstanceOf(ApiException.class);
  }

  @Test
  @DisplayName("仅出现 ENTITY 字样的注释不会被误判为攻击（不过度拒绝）")
  void benignCommentIsNotOverRejected() {
    // 实测确认：注释里的 "ENTITY" 不含 "<!ENTITY" 序列，因此不会被拒绝。
    // 这条断言固化"不过度拒绝"，避免将来把规则改得过宽而误伤真实 nmap 输出。
    String xml = "<nmaprun><!-- ENTITY 只是注释文字 --><host><status state=\"up\"/></host></nmaprun>";
    assertThatCode(() -> parser.parse(xml)).doesNotThrowAnyException();
    assertThat(parser.parse(xml).hostStatuses()).hasSize(1);
  }
}
