package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.asset.DiscoveredPath;
import com.bachelor.toolbox.asset.DiscoveredPathService;
import com.bachelor.toolbox.recon.ReconResult;
import com.bachelor.toolbox.recon.ReconService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 第376轮：site_crawl 的任务结果不得把全部已发现路径整包塞进 resultJson。
 *
 * <p>{@code DiscoveredPathService.list} 上限是 20,000 行，而 {@code SiteCrawlTool} 把取到的
 * **每一条**路径都放进 {@code data.paths}。一次爬取的结果 JSON 会被持久化到
 * {@code security_tasks.result_json}，并经 {@code GET /api/tasks/{id}} 返回给界面：
 * 2 万条路径约数百 KB~数 MB，逐次累积成可观的库体与响应体膨胀，且每次打开任务详情都要全量传输。
 *
 * <p>修复要求：结果里只带有限条样本，并**显式**给出总数与是否截断（不得静默丢弃）。
 */
@DisplayName("site_crawl 结果路径数必须封顶（第376轮）")
class SiteCrawlToolResultBoundTests {

  private static DiscoveredPath path(long id) {
    DiscoveredPath path = new DiscoveredPath();
    path.setId(id);
    path.setUrl("http://192.168.222.155/p" + id + "?id=" + id);
    path.setPath("/p" + id + "?id=" + id);
    path.setSource("PASSIVE_LINK");
    path.setNote("note");
    return path;
  }

  private static ToolExecutionResult run(int pathCount) {
    ReconService recon = mock(ReconService.class);
    DiscoveredPathService discovered = mock(DiscoveredPathService.class);
    when(recon.collect(anyLong(), any())).thenReturn(mock(ReconResult.class));
    List<DiscoveredPath> all = new ArrayList<>();
    for (int i = 0; i < pathCount; i++) all.add(path(i));
    when(discovered.list(anyLong(), anyLong())).thenReturn(all);

    SiteCrawlTool tool = new SiteCrawlTool(recon, discovered);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(376L);
    target.setTargetValue("http://192.168.222.155/");
    target.setAllowedPorts("80");
    target.setEnabled(true);
    return tool.executeScoped(519L, target, Map.of(), ToolExecutionObserver.NOOP);
  }

  @Test
  @DisplayName("路径很多时结果只带有限样本，并显式标记截断")
  void manyPathsAreTruncatedWithExplicitFlag() {
    ToolExecutionResult result = run(2000);
    Map<String, Object> data = result.data();
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> paths = (List<Map<String, Object>>) data.get("paths");

    assertThat(paths.size()).as("结果中的路径条数必须封顶").isLessThanOrEqualTo(500);
    assertThat(data.get("pathsTotal")).as("必须给出真实总数").isEqualTo(2000);
    assertThat(data.get("pathsTruncated")).as("必须显式标记已截断").isEqualTo(true);
  }

  @Test
  @DisplayName("路径不多时不截断，且条数与总数一致")
  void fewPathsAreNotTruncated() {
    ToolExecutionResult result = run(34);
    Map<String, Object> data = result.data();
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> paths = (List<Map<String, Object>>) data.get("paths");

    assertThat(paths).hasSize(34);
    assertThat(data.get("pathsTotal")).isEqualTo(34);
    assertThat(data.get("pathsTruncated")).isEqualTo(false);
  }
}
