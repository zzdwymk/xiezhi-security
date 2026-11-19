package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.target.TargetService;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class IcpCaptchaControllerBoundaryTests {
  private final IcpChallengeStore challenges = mock(IcpChallengeStore.class);
  private final IcpBrowserCaptureStore captures = mock(IcpBrowserCaptureStore.class);
  private final AssessmentProjectService projects = mock(AssessmentProjectService.class);
  private final AuthorizedTargetRepository targets = mock(AuthorizedTargetRepository.class);
  private final TargetService authorization = mock(TargetService.class);

  private IcpCaptchaController controller() {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(2L);
    target.setTargetValue("https://example.test");
    when(targets.findById(2L)).thenReturn(Optional.of(target));
    when(authorization.getCurrentlyAuthorized(2L, 1L)).thenReturn(target);
    return new IcpCaptchaController(challenges, captures, projects, targets, authorization);
  }

  private Map<String, Object> capture(String domain) {
    Map<String, Object> row = new LinkedHashMap<>();
    row.put("owner", "QA operator");
    row.put("domain", domain);
    return controller().capture(1L, new IcpCaptchaController.BrowserCaptureRequest(2L, List.of(row)));
  }

  @Test
  @SuppressWarnings("unchecked")
  void hostlessCapturedUriDoesNotCrashAndFallsBackToQueriedDomain() {
    Map<String, Object> response = capture("file:///tmp/qa-only.html");
    List<Map<String, Object>> records = (List<Map<String, Object>>) response.get("records");
    assertThat(records).hasSize(1);
    assertThat(records.get(0).get("domain")).isEqualTo("example.test");
  }

  @Test
  @SuppressWarnings("unchecked")
  void ordinaryHttpsCaptureKeepsCanonicalDomain() {
    Map<String, Object> response = capture("https://www.example.test/path");
    List<Map<String, Object>> records = (List<Map<String, Object>>) response.get("records");
    assertThat(records.get(0).get("domain")).isEqualTo("example.test");
  }

  @Test
  void unauthorizedProjectStopsBeforeCreatingExternalClient() {
    IcpCaptchaController controller = controller();
    doThrow(new ApiException("无权访问该评估项目")).when(projects).validateProjectTarget(1L, 2L);
    try (var clients = mockConstruction(MiitIcpClient.class)) {
      assertThatThrownBy(() -> controller.begin(1L, new IcpCaptchaController.CaptchaBeginRequest(2L)))
          .isInstanceOf(ApiException.class);
      assertThat(clients.constructed()).isEmpty();
      verify(challenges, never()).register(any());
    }
  }
}
