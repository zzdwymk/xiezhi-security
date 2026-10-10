package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.ai.AiAgentRuntimeClient;
import com.bachelor.toolbox.ai.AiProjectIndexService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/** A read-only task whose project boundary comes from the persisted task, never its parameters. */
@Component
public class ProjectContextRetrievalTool implements SecurityTool {
  public static final String DEFAULT_QUERY = "当前目标的授权范围、扫描发现与待核实证据";
  private final AssessmentProjectService projects;
  private final AiProjectIndexService index;
  private final AiAgentRuntimeClient runtime;

  public ProjectContextRetrievalTool(AssessmentProjectService projects,
      AiProjectIndexService index, AiAgentRuntimeClient runtime) {
    this.projects = projects;
    this.index = index;
    this.runtime = runtime;
  }

  @Override public String code() { return "retrieve_project_context"; }
  @Override public String displayName() { return "项目资料检索"; }
  @Override public String description() { return "按查询内容检索当前项目与目标的已有资料，并保存证据摘要；不访问检测目标。"; }

  @Override
  public ToolExecutionResult execute(AuthorizedTarget target, Map<String, Object> parameters) {
    throw new ApiException("项目资料检索必须由带有项目归属的任务执行");
  }

  public ToolExecutionResult executeScoped(Long projectId, AuthorizedTarget target,
      Map<String, Object> parameters, ToolExecutionObserver observer) {
    String query = query(parameters);
    if (projectId == null || projectId <= 0 || target == null || target.getId() == null) {
      throw new ApiException("项目资料检索缺少项目或目标归属");
    }
    projects.validateProjectTargetMembership(projectId, target.getId());
    observer.heartbeat("正在更新当前项目的可检索资料");
    if (observer.isCancellationRequested()) throw new ApiException("资料检索已取消");
    if (!index.refreshBestEffort(projectId)) {
      throw new ApiException("项目资料索引更新失败，请检查 AI 服务后重试");
    }
    if (observer.isCancellationRequested()) throw new ApiException("资料检索已取消");
    observer.heartbeat("正在检索当前目标的相关证据");
    Map<String, Object> evidence = runtime.retrieveProjectEvidence(projectId, target.getId(), query);
    if (observer.isCancellationRequested()) throw new ApiException("资料检索已取消");
    int count = ((List<?>) evidence.get("items")).size();
    return new ToolExecutionResult(count == 0
        ? "资料检索完成，未找到与查询匹配的已有证据；这不代表目标不存在风险。"
        : "资料检索完成，找到 " + count + " 条相关证据。", evidence, List.of());
  }

  public static String query(Map<String, Object> parameters) {
    if (parameters == null || parameters.isEmpty()) return DEFAULT_QUERY;
    if (parameters.keySet().stream().anyMatch(key -> !"query".equals(key))) {
      throw new ApiException("资料检索仅支持查询内容参数");
    }
    Object raw = parameters.get("query");
    if (!(raw instanceof String value) || value.length() > 2000) {
      throw new ApiException("资料检索的查询内容应为不超过 2000 字的文本");
    }
    return value.isBlank() ? DEFAULT_QUERY : value.strip();
  }
}
