package com.bachelor.toolbox.postscan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.ai.AiDispatchResponse;
import com.bachelor.toolbox.ai.AiModelClient;
import com.bachelor.toolbox.ai.AiPlanResponse;
import com.bachelor.toolbox.ai.AiAgentRequest;
import com.bachelor.toolbox.ai.SecurityAgentTools;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.bachelor.toolbox.vulnerability.VulnerabilityDefinitionRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PostScanPathServiceTests {
  private static final long PROJECT = 1L;
  private final PostScanPathRepository pathRepository = mock(PostScanPathRepository.class);
  private final ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
  private final AssessmentProjectService projectService = mock(AssessmentProjectService.class);
  private final TargetService targetService = mock(TargetService.class);  private final FindingRepository findingRepository = mock(FindingRepository.class);
  private final SecurityTaskRepository taskRepository = mock(SecurityTaskRepository.class);
  private final VulnerabilityDefinitionRepository vulnerabilityRepository =
      mock(VulnerabilityDefinitionRepository.class);
  private final AiModelClient modelClient = mock(AiModelClient.class);
  private final SecurityAgentTools agentTools = mock(SecurityAgentTools.class);
  private final AuditService auditService = mock(AuditService.class);
  private final AtomicReference<PostScanPath> savedPath = new AtomicReference<>();
  private PostScanPathService service;
  private AuthorizedTarget target;
  private Finding finding;
  private SecurityTask sourceTask;

  @BeforeEach
  void setUp() {
    service =
        new PostScanPathService(
            pathRepository,
            authorization,
            projectService,
            targetService,
            findingRepository,
            taskRepository,
            vulnerabilityRepository,
            modelClient,
            agentTools,
            auditService,
            new ObjectMapper());    target = new AuthorizedTarget();
    target.setId(7L);
    target.setName("local web");
    target.setTargetType("URL");
    target.setTargetValue("https://127.0.0.1:8443");
    target.setAllowedPorts("8443");
    target.setEnabled(true);
    finding = new Finding();
    finding.setId(11L);
    finding.setTaskId(21L);
    finding.setTargetId(7L);
    finding.setTitle("敏感 Cookie 缺少安全属性: JSESSIONID");
    finding.setSeverity("HIGH");
    finding.setStatus("OPEN");
    finding.setSourceTool("http_security_check");
    finding.setVulnerabilityCode("STB-WEB-002");
    finding.setEvidence("cookie=JSESSIONID; missing=Secure,HttpOnly");
    sourceTask = new SecurityTask();
    sourceTask.setId(21L);
    sourceTask.setProjectId(PROJECT);
    sourceTask.setTargetId(7L);
    sourceTask.setToolCode("http_security_check");
    sourceTask.setStatus("SUCCESS");    when(targetService.get(7L)).thenReturn(target);
    when(findingRepository.findAllById(any())).thenReturn(List.of(finding));
    when(taskRepository.findAllById(any())).thenReturn(List.of(sourceTask));
    when(taskRepository.existsByTargetIdAndStatusIn(7L, List.of("PENDING", "RUNNING")))
        .thenReturn(false);
    when(vulnerabilityRepository.findByVulnerabilityCode(any())).thenReturn(Optional.empty());
    when(modelClient.enabled()).thenReturn(false);
    when(modelClient.model()).thenReturn("test-model");
    when(pathRepository.save(any(PostScanPath.class)))
        .thenAnswer(
            invocation -> {
              PostScanPath value = invocation.getArgument(0);
              if (value.getId() == null) value.setId(31L);
              savedPath.set(value);
              return value;
            });
    when(pathRepository.findById(31L)).thenAnswer(ignored -> Optional.ofNullable(savedPath.get()));
  }

  @Test
  void planCreatesNoTaskAndConfirmedSafeStepsDispatchOnce() throws Exception {
    PostScanPathResponse planned =
        service.plan(new PostScanPathRequest(PROJECT, 7L, List.of(11L), "生成后续授权验证路径"));
    assertThat(planned.status()).isEqualTo("DRAFT");
    assertThat(planned.steps())
        .anyMatch(step -> step.automated() && "SAFE".equals(step.riskLevel()));
    assertThat(planned.steps())
        .anyMatch(step -> !step.automated() && "CAUTION".equals(step.riskLevel()));
    verify(agentTools, never())
        .executeAuthorizedPlan(any(AiAgentRequest.class), any(AiPlanResponse.class));

    AiPlanResponse executedPlan = new AiPlanResponse("local", "test", "ok", false, List.of());
    when(agentTools.executeAuthorizedPlan(any(AiAgentRequest.class), any(AiPlanResponse.class)))
        .thenReturn(new AiDispatchResponse(7L, executedPlan, 2, List.of(101L, 102L)));
    List<String> selected =
        planned.steps().stream()
            .filter(PostScanPathResponse.RecommendedStep::automated)
            .map(PostScanPathResponse.RecommendedStep::id)
            .toList();
    PostScanPathResponse first = service.confirm(31L, new PostScanConfirmRequest(true, selected));
    PostScanPathResponse replay = service.confirm(31L, new PostScanConfirmRequest(true, selected));

    assertThat(first.status()).isEqualTo("DISPATCHED");
    assertThat(first.taskIds()).containsExactly(101L, 102L);
    assertThat(replay.taskIds()).containsExactly(101L, 102L);
    verify(agentTools, times(1))
        .executeAuthorizedPlan(any(AiAgentRequest.class), any(AiPlanResponse.class));
  }

  @Test
  void rejectsFindingFromAnotherTargetBeforePlanning() throws Exception {
    finding.setTargetId(8L);

    assertThatThrownBy(() -> service.plan(new PostScanPathRequest(PROJECT, 7L, List.of(11L), "follow up")))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不属于当前授权目标");    verify(pathRepository, never()).save(any());
    verify(agentTools, never()).executeAuthorizedPlan(any(), any());
  }
}
