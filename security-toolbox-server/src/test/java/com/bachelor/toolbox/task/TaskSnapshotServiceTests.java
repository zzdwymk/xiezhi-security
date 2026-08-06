package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.dependency.DependencyDetectionService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.tool.SecurityTool;
import com.bachelor.toolbox.vulnerability.DetectionRule;
import com.bachelor.toolbox.vulnerability.DetectionRuleRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

class TaskSnapshotServiceTests {
  @TempDir Path tempDirectory;

  @Test
  void hidesSerializationDetailsFromSnapshotFailure() throws Exception {
    ObjectMapper objectMapper = mock(ObjectMapper.class);
    when(objectMapper.writeValueAsString(any()))
        .thenThrow(new JsonProcessingException("jdbc:postgresql://secret-host/toolbox") {});
    TaskSnapshotService service =
        new TaskSnapshotService(
            objectMapper,
            mock(DetectionRuleRepository.class),
            mock(DependencyDetectionService.class),
            tempDirectory.toString());
    SecurityTask task = new SecurityTask();
    task.setId(42L);
    task.setToolCode("test_tool");

    assertThatThrownBy(() -> service.capture(task, target(), mock(SecurityTool.class)))
        .isInstanceOf(ApiException.class)
        .hasMessage("无法生成任务授权与执行环境快照，请稍后重试")
        .hasMessageNotContaining("secret-host")
        .hasMessageNotContaining("JsonProcessingException")
        .hasMessageNotContaining("jdbc");
  }

  @Test
  void resolvesRuleVersionByRuleCode() {
    DetectionRuleRepository rules = mock(DetectionRuleRepository.class);
    DetectionRule rule = new DetectionRule();
    rule.setRuleCode("RULE-HTTP");
    rule.setVulnerabilityCode("CVE-TEST");
    rule.setName("HTTP 检测规则");
    rule.setToolCode("http_probe");
    when(rules.findByRuleCode("RULE-HTTP")).thenReturn(Optional.of(rule));
    TaskSnapshotService service =
        new TaskSnapshotService(
            new ObjectMapper(),
            rules,
            mock(DependencyDetectionService.class),
            tempDirectory.toString());

    String version = ReflectionTestUtils.invokeMethod(service, "resolveRuleVersion", "RULE-HTTP");

    assertThat(version).isNotBlank();
    verify(rules).findByRuleCode("RULE-HTTP");
  }

  private AuthorizedTarget target() {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(7L);
    target.setName("授权目标");
    target.setTargetValue("https://example.test");
    target.setTargetType("URL");
    target.setAuthorizationNote("已授权");
    return target;
  }
}
