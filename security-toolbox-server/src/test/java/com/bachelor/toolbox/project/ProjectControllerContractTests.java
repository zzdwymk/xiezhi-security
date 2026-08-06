package com.bachelor.toolbox.project;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;

class ProjectControllerContractTests {
  private final AssessmentProjectService projectService = mock(AssessmentProjectService.class);
  private final AssessmentProjectController projectController =
      new AssessmentProjectController(projectService);
  private final ProjectApprovalService approvalService = mock(ProjectApprovalService.class);
  private final ProjectApprovalController approvalController =
      new ProjectApprovalController(approvalService);

  @Test
  void keepsAssessmentProjectApiPathsAndResponseStatusesCompatible() throws NoSuchMethodException {
    assertBasePath(AssessmentProjectController.class, "/api/projects");

    assertGetPath(AssessmentProjectController.class, "list", "");
    assertGetPath(AssessmentProjectController.class, "get", "/{id}", Long.class);
    assertPostPath(AssessmentProjectController.class, "create", "", ProjectDtos.Create.class);
    assertResponseStatus(
        AssessmentProjectController.class.getDeclaredMethod("create", ProjectDtos.Create.class),
        HttpStatus.CREATED);
    assertPutPath(
        AssessmentProjectController.class, "update", "/{id}", Long.class, ProjectDtos.Update.class);
    assertPostPath(
        AssessmentProjectController.class,
        "status",
        "/{id}/status",
        Long.class,
        ProjectDtos.Status.class);
    assertGetPath(AssessmentProjectController.class, "summary", "/{id}/summary", Long.class);
    assertGetPath(AssessmentProjectController.class, "tasks", "/{id}/tasks", Long.class);
    assertGetPath(AssessmentProjectController.class, "findings", "/{id}/findings", Long.class);
    assertGetPath(AssessmentProjectController.class, "audits", "/{id}/audits", Long.class);
    assertGetPath(AssessmentProjectController.class, "targets", "/{id}/targets", Long.class);
    assertPostPath(
        AssessmentProjectController.class,
        "addTarget",
        "/{id}/targets/{targetId}",
        Long.class,
        Long.class);
    Method addTarget =
        AssessmentProjectController.class.getDeclaredMethod("addTarget", Long.class, Long.class);
    assertResponseStatus(addTarget, HttpStatus.CREATED);
    assertDeletePath(
        AssessmentProjectController.class,
        "removeTarget",
        "/{id}/targets/{targetId}",
        Long.class,
        Long.class);
    Method removeTarget =
        AssessmentProjectController.class.getDeclaredMethod("removeTarget", Long.class, Long.class);
    assertResponseStatus(removeTarget, HttpStatus.NO_CONTENT);
  }

  @Test
  void keepsApprovalApiPathsCompatible() throws NoSuchMethodException {
    assertBasePath(ProjectApprovalController.class, "/api/projects/{projectId}/approvals");
    assertGetPath(ProjectApprovalController.class, "list", "", Long.class);
    assertPostPath(ProjectApprovalController.class, "request", "", Long.class, Map.class);
    assertPostPath(
        ProjectApprovalController.class,
        "decide",
        "/{approvalId}/decision",
        Long.class,
        Long.class,
        Map.class);
  }

  @Test
  void keepsProjectRequestAndSummaryJsonFieldsCompatible() {
    assertThat(recordComponentNames(ProjectDtos.Create.class))
        .containsExactly(
            "name",
            "description",
            "authorizationStatement",
            "authorizationValidFrom",
            "authorizationExpiresAt",
            "owner");
    assertThat(recordComponentNames(ProjectDtos.Update.class))
        .containsExactly(
            "name",
            "description",
            "authorizationStatement",
            "authorizationValidFrom",
            "authorizationExpiresAt",
            "owner");
    assertThat(recordComponentNames(ProjectDtos.Status.class)).containsExactly("status");
    assertThat(recordComponentNames(ProjectDtos.Summary.class))
        .containsExactly(
            "project",
            "targetCount",
            "taskCount",
            "vulnerabilityCount",
            "informationalCount",
            "retestCount",
            "auditCount");
  }

  @Test
  void delegatesAssessmentProjectCrudWithoutTransformingArguments() {
    AssessmentProject project = new AssessmentProject();
    ProjectDtos.Create create =
        new ProjectDtos.Create(
            "项目",
            null,
            "授权",
            java.time.Instant.parse("2026-01-01T00:00:00Z"),
            java.time.Instant.parse("2026-01-02T00:00:00Z"),
            "负责人");
    ProjectDtos.Update update = new ProjectDtos.Update("新名称", null, null, null, null, null);
    ProjectDtos.Status status = new ProjectDtos.Status("ACTIVE");
    when(projectService.get(1L)).thenReturn(project);
    when(projectService.create(create)).thenReturn(project);
    when(projectService.update(1L, update)).thenReturn(project);
    when(projectService.updateStatus(1L, "ACTIVE")).thenReturn(project);

    assertThat(projectController.get(1L)).isSameAs(project);
    assertThat(projectController.create(create)).isSameAs(project);
    assertThat(projectController.update(1L, update)).isSameAs(project);
    assertThat(projectController.status(1L, status)).isSameAs(project);

    verify(projectService).get(1L);
    verify(projectService).create(create);
    verify(projectService).update(1L, update);
    verify(projectService).updateStatus(1L, "ACTIVE");
  }

  @Test
  void preservesApprovalDefaultsAndExplicitValues() {
    ProjectApproval approval = new ProjectApproval();
    when(approvalService.request(1L, "SCAN", null, null)).thenReturn(approval);
    when(approvalService.decide(1L, 2L, "APPROVED", null)).thenReturn(approval);
    Map<String, String> explicitRequest =
        Map.of("action", "REPORT", "comment", "生成报告", "authorizationSnapshotHash", "hash");
    Map<String, String> explicitDecision = Map.of("status", "REJECTED", "comment", "驳回");

    assertThat(approvalController.request(1L, Map.of())).isSameAs(approval);
    assertThat(approvalController.decide(1L, 2L, Map.of())).isSameAs(approval);
    approvalController.request(1L, explicitRequest);
    approvalController.decide(1L, 2L, explicitDecision);

    verify(approvalService).request(1L, "SCAN", null, null);
    verify(approvalService).decide(1L, 2L, "APPROVED", null);
    verify(approvalService).request(1L, "REPORT", "生成报告", "hash");
    verify(approvalService).decide(1L, 2L, "REJECTED", "驳回");
  }

  @Test
  void preservesExplicitNullApprovalStatusInsteadOfApplyingDefault() {
    Map<String, String> request = new HashMap<>();
    request.put("action", null);
    Map<String, String> decision = new HashMap<>();
    decision.put("status", null);

    approvalController.request(1L, request);
    approvalController.decide(1L, 2L, decision);

    verify(approvalService).request(1L, null, null, null);
    verify(approvalService).decide(1L, 2L, null, null);
  }

  private void assertBasePath(Class<?> controllerType, String path) {
    RequestMapping mapping = controllerType.getAnnotation(RequestMapping.class);
    assertThat(mapping.value()).containsExactly(path);
  }

  private void assertGetPath(
      Class<?> controllerType, String methodName, String path, Class<?>... parameterTypes)
      throws NoSuchMethodException {
    GetMapping mapping =
        controllerType
            .getDeclaredMethod(methodName, parameterTypes)
            .getAnnotation(GetMapping.class);
    assertPath(mapping.value(), path);
  }

  private void assertPostPath(
      Class<?> controllerType, String methodName, String path, Class<?>... parameterTypes)
      throws NoSuchMethodException {
    PostMapping mapping =
        controllerType
            .getDeclaredMethod(methodName, parameterTypes)
            .getAnnotation(PostMapping.class);
    assertPath(mapping.value(), path);
  }

  private void assertPutPath(
      Class<?> controllerType, String methodName, String path, Class<?>... parameterTypes)
      throws NoSuchMethodException {
    PutMapping mapping =
        controllerType
            .getDeclaredMethod(methodName, parameterTypes)
            .getAnnotation(PutMapping.class);
    assertPath(mapping.value(), path);
  }

  private void assertDeletePath(
      Class<?> controllerType, String methodName, String path, Class<?>... parameterTypes)
      throws NoSuchMethodException {
    DeleteMapping mapping =
        controllerType
            .getDeclaredMethod(methodName, parameterTypes)
            .getAnnotation(DeleteMapping.class);
    assertPath(mapping.value(), path);
  }

  private void assertPath(String[] paths, String expected) {
    if (expected.isEmpty()) {
      assertThat(paths).isEmpty();
    } else {
      assertThat(paths).containsExactly(expected);
    }
  }

  private void assertResponseStatus(Method method, HttpStatus status) {
    assertThat(method.getAnnotation(ResponseStatus.class).value()).isEqualTo(status);
  }

  private List<String> recordComponentNames(Class<?> recordType) {
    return Arrays.stream(recordType.getRecordComponents()).map(RecordComponent::getName).toList();
  }
}
