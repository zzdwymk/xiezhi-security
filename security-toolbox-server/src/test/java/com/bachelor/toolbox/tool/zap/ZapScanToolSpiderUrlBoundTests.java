package com.bachelor.toolbox.tool.zap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.tool.ToolExecutionObserver;
import com.bachelor.toolbox.tool.ToolExecutionResult;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 第378轮：ZAP 结果的爬取 URL 列表必须封顶。
 *
 * <p>{@code data.spiderUrls} 此前把 ZAP spider 的全部 URL 原样写入，大站点可达上万条，
 * 结果随任务持久化到 {@code result_json} 并经任务详情接口回传——与 site_crawl（第376轮）
 * 同类的无界载荷问题。
 */
@DisplayName("ZAP 结果爬取 URL 封顶（第378轮）")
class ZapScanToolSpiderUrlBoundTests {

  private static AuthorizedTarget target() {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(378L);
    target.setTargetValue("http://127.0.0.1:8080/");
    target.setTargetType("URL");
    target.setAllowedPorts("8080");
    target.setEnabled(true);
    return target;
  }

  private static ToolExecutionResult run(int urlCount) throws Exception {
    List<String> urls = new ArrayList<>();
    for (int i = 0; i < urlCount; i++) urls.add("http://127.0.0.1:8080/page" + i);
    ZapDaemon daemon = new ZapDaemon() {
      @Override public boolean isReady() { return true; }
      @Override public void start() {}
      @Override public void includeInScope(URI target) {}
      @Override public String startSpider(URI target) { return "1"; }
      @Override public int spiderProgress(String taskId) { return 100; }
      @Override public void stopSpider(String taskId) {}
      @Override public String startActiveScan(URI target) { return "2"; }
      @Override public int activeScanProgress(String scanId) { return 100; }
      @Override public void stopActiveScan(String scanId) {}
      @Override public List<ZapAlert> alerts() { return List.of(); }
      @Override public long passiveScanRemaining() { return 0; }
      @Override public List<String> crawlResults(URI target) { return urls; }
      @Override public List<String> technologies(URI target) { return List.of(); }
      @Override public boolean importOpenApi(String url) { return false; }
      @Override public void kill() {}
      @Override public void close() {}
    };
    ZapScanTool tool = new ZapScanTool(new TargetPolicyService(false, new PortRangeParser()), () -> daemon, 60);
    return tool.execute(target(), Map.of("mode", "passive"), ToolExecutionObserver.NOOP);
  }

  @Test
  @DisplayName("大量爬取 URL 时结果封顶并给出总数与截断标记")
  void spiderUrlsAreCappedWithExplicitCounts() throws Exception {
    Map<String, Object> data = run(2000).data();
    @SuppressWarnings("unchecked")
    List<String> spiderUrls = (List<String>) data.get("spiderUrls");
    assertThat(spiderUrls).as("spiderUrls 必须封顶").hasSizeLessThanOrEqualTo(500);
    assertThat(data.get("spiderUrlCount")).isEqualTo(2000);
    assertThat(data.get("spiderUrlsReturned")).isEqualTo(spiderUrls.size());
    assertThat(data.get("spiderUrlsTruncated")).isEqualTo(true);
  }

  @Test
  @DisplayName("URL 不多时不截断")
  void fewSpiderUrlsAreNotTruncated() throws Exception {
    Map<String, Object> data = run(12).data();
    assertThat(data.get("spiderUrlCount")).isEqualTo(12);
    assertThat(data.get("spiderUrlsTruncated")).isEqualTo(false);
  }
}
