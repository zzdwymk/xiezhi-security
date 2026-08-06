package com.bachelor.toolbox.operation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.RecordComponent;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

class SecurityActionControllerTests {
  private final SecurityActionService service = mock(SecurityActionService.class);
  private final SecurityActionController controller = new SecurityActionController(service);
  private final Authentication authentication = mock(Authentication.class);

  @Test
  void keepsApiPathsCompatible() throws NoSuchMethodException {
    RequestMapping baseMapping = SecurityActionController.class.getAnnotation(RequestMapping.class);
    assertThat(baseMapping.value()).containsExactly("/api/projects/{projectId}/security-actions");

    GetMapping listMapping =
        SecurityActionController.class
            .getDeclaredMethod("list", Long.class)
            .getAnnotation(GetMapping.class);
    assertThat(listMapping.value()).isEmpty();

    assertPostPath("create", "", Long.class, SecurityActionDtos.Create.class, Authentication.class);
    assertPostPath(
        "decide",
        "/{id}/decision",
        Long.class,
        Long.class,
        SecurityActionDtos.Decision.class,
        Authentication.class);
    assertPostPath("start", "/{id}/start", Long.class, Long.class);
    assertPostPath(
        "complete", "/{id}/complete", Long.class, Long.class, SecurityActionDtos.Complete.class);
    assertPostPath(
        "rollback", "/{id}/rollback", Long.class, Long.class, SecurityActionDtos.Rollback.class);
  }

  @Test
  void keepsRequestJsonFieldsCompatible() {
    assertThat(recordComponentNames(SecurityActionDtos.Create.class))
        .containsExactly(
            "targetId",
            "findingId",
            "category",
            "title",
            "purpose",
            "riskLevel",
            "nonDestructive",
            "lateralMovement",
            "executionPlan",
            "rollbackPlan",
            "windowStart",
            "windowEnd");
    assertThat(recordComponentNames(SecurityActionDtos.Decision.class))
        .containsExactly("decision", "comment");
    assertThat(recordComponentNames(SecurityActionDtos.Complete.class))
        .containsExactly("evidence", "terminationReason");
    assertThat(recordComponentNames(SecurityActionDtos.Rollback.class))
        .containsExactly("evidence", "reason");
  }

  @Test
  void delegatesAllOperationsWithoutTransformingArguments() {
    SecurityAction action = new SecurityAction();
    SecurityActionDtos.Create createRequest = createRequest();
    SecurityActionDtos.Decision decisionRequest = new SecurityActionDtos.Decision("APPROVED", "同意");
    SecurityActionDtos.Complete completeRequest = new SecurityActionDtos.Complete("证据", "完成");
    SecurityActionDtos.Rollback rollbackRequest = new SecurityActionDtos.Rollback("证据", "恢复");

    when(service.list(1L)).thenReturn(List.of(action));
    when(service.create(1L, createRequest, authentication)).thenReturn(action);
    when(service.decide(1L, 2L, decisionRequest, authentication)).thenReturn(action);
    when(service.start(1L, 2L)).thenReturn(action);
    when(service.complete(1L, 2L, completeRequest)).thenReturn(action);
    when(service.rollback(1L, 2L, rollbackRequest)).thenReturn(action);

    assertThat(controller.list(1L)).containsExactly(action);
    assertThat(controller.create(1L, createRequest, authentication)).isSameAs(action);
    assertThat(controller.decide(1L, 2L, decisionRequest, authentication)).isSameAs(action);
    assertThat(controller.start(1L, 2L)).isSameAs(action);
    assertThat(controller.complete(1L, 2L, completeRequest)).isSameAs(action);
    assertThat(controller.rollback(1L, 2L, rollbackRequest)).isSameAs(action);

    verify(service).list(1L);
    verify(service).create(1L, createRequest, authentication);
    verify(service).decide(1L, 2L, decisionRequest, authentication);
    verify(service).start(1L, 2L);
    verify(service).complete(1L, 2L, completeRequest);
    verify(service).rollback(1L, 2L, rollbackRequest);
  }

  private void assertPostPath(String methodName, String path, Class<?>... parameterTypes)
      throws NoSuchMethodException {
    PostMapping mapping =
        SecurityActionController.class
            .getDeclaredMethod(methodName, parameterTypes)
            .getAnnotation(PostMapping.class);
    if (path.isEmpty()) {
      assertThat(mapping.value()).isEmpty();
    } else {
      assertThat(mapping.value()).containsExactly(path);
    }
  }

  private List<String> recordComponentNames(Class<?> recordType) {
    return Arrays.stream(recordType.getRecordComponents()).map(RecordComponent::getName).toList();
  }

  private SecurityActionDtos.Create createRequest() {
    Instant start = Instant.now().plusSeconds(60);
    return new SecurityActionDtos.Create(
        7L,
        null,
        "VULNERABILITY_VALIDATION",
        "授权验证",
        "验证目的",
        "MEDIUM",
        true,
        false,
        "执行计划",
        "回滚计划",
        start,
        start.plusSeconds(1800));
  }
}
