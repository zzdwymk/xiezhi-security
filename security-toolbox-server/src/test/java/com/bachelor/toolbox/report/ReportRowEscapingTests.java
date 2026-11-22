package com.bachelor.toolbox.report;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.ai.AiAnswerService;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.task.TaskService;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import org.junit.jupiter.api.Test;

/**
 * 第297轮：{@code ReportService.row(...)} 不得按"内容里有没有 &lt;br&gt;"决定是否原样输出 HTML。
 *
 * <p>该按内容猜测的放行规则意味着：任何调用方只要传入的文本里出现 {@code <br>}，其后的标签就不再
 * 转义。报告的 CSP 会挡住脚本执行，但伪造内容、注入钓鱼链接、改写版式仍然成立。表格单元应当
 * 一律转义；需要嵌 HTML 的地方走显式的 {@code rowHtml}。
 */
class ReportRowEscapingTests {
  private ReportService service() {
    return new ReportService(
        mock(TaskService.class),
        mock(AuthorizedTargetRepository.class),
        mock(FindingRepository.class),
        mock(AiAnswerService.class));
  }

  @Test
  void lineBreakMarkersDoNotBypassEscaping() {
    String html = service().row("错误信息", "失败<br><img src=x onerror=alert(1)>");
    assertThat(html).as("表格单元一律转义").contains("&lt;img").doesNotContain("<img src=x");
  }

  @Test
  void preBlocksPassedToRowAreEscapedToo() {
    String html = service().row("请求参数", "<pre><code>x</code></pre>");
    assertThat(html)
        .as("row 是纯文本单元：连 <pre> 也必须转义；需要 HTML 结构的调用方必须显式走 rowHtml")
        .contains("&lt;pre&gt;")
        .doesNotContain("<pre><code>");
  }
}
