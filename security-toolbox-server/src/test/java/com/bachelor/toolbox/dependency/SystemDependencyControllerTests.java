package com.bachelor.toolbox.dependency;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class SystemDependencyControllerTests {
  @Mock private DependencyDetectionService detectionService;
  @Mock private HttpServletRequest request;
  @InjectMocks private SystemDependencyController controller;

  @Test
  void returnsDependenciesForLoopbackRequest() {
    SystemDependenciesResponse expected =
        new SystemDependenciesResponse("Windows", "amd64", List.of());
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");
    when(detectionService.detect()).thenReturn(expected);

    assertThat(controller.dependencies(request)).isSameAs(expected);
  }

  @Test
  void returnsHealthForIpv6LoopbackRequest() {
    when(request.getRemoteAddr()).thenReturn("::1");

    assertThat(controller.health(request)).containsEntry("status", "UP");
    verifyNoInteractions(detectionService);
  }

  @Test
  void rejectsRemoteDependencyStatusRequestWithChineseMessage() {
    when(request.getRemoteAddr()).thenReturn("192.0.2.10");

    assertThatThrownBy(() -> controller.dependencies(request))
        .isInstanceOfSatisfying(
            ResponseStatusException.class,
            exception -> {
              assertThat(exception.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
              assertThat(exception.getReason()).isEqualTo("依赖状态仅允许从本机访问");
            });
    verifyNoInteractions(detectionService);
  }

  @Test
  void rejectsRemoteHealthRequestWithChineseMessage() {
    when(request.getRemoteAddr()).thenReturn("192.0.2.10");

    assertThatThrownBy(() -> controller.health(request))
        .isInstanceOfSatisfying(
            ResponseStatusException.class,
            exception -> {
              assertThat(exception.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
              assertThat(exception.getReason()).isEqualTo("健康状态仅允许从本机访问");
            });
    verifyNoInteractions(detectionService);
  }

  @Test
  void rejectsMissingRemoteAddress() {
    when(request.getRemoteAddr()).thenReturn(null);

    assertThatThrownBy(() -> controller.dependencies(request))
        .isInstanceOfSatisfying(
            ResponseStatusException.class,
            exception -> {
              assertThat(exception.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
              assertThat(exception.getReason()).isEqualTo("依赖状态仅允许从本机访问");
            });
    verifyNoInteractions(detectionService);
  }

  @Test
  void rejectsRemoteShutdownRequestBeforeCheckingToken() {
    when(request.getRemoteAddr()).thenReturn("192.0.2.10");

    assertThatThrownBy(() -> controller.shutdown(request, "anything"))
        .isInstanceOfSatisfying(
            ResponseStatusException.class,
            exception -> {
              assertThat(exception.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
              assertThat(exception.getReason()).isEqualTo("关机操作仅允许从本机访问");
            });
    verifyNoInteractions(detectionService);
  }
}
