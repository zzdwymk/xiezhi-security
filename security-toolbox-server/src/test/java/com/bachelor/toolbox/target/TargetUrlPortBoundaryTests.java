package com.bachelor.toolbox.target;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectRepository;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TargetUrlPortBoundaryTests {
  private final AuthorizedTargetRepository repository = mock(AuthorizedTargetRepository.class);
  private final AssessmentProjectRepository projects = mock(AssessmentProjectRepository.class);
  private final ProjectTargetRepository links = mock(ProjectTargetRepository.class);
  private final ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
  private final TargetService service = new TargetService(repository, mock(AuditService.class),
      new PortRangeParser(), projects, links, authorization, 65535);

  @BeforeEach
  void setup() {
    AssessmentProject project = new AssessmentProject();
    project.setStatus("ACTIVE");
    when(projects.findById(519L)).thenReturn(Optional.of(project));
    when(authorization.isAdmin()).thenReturn(true);
    when(links.findByProjectId(519L)).thenReturn(List.of());
    when(repository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
  }

  private TargetRequest request(String value) {
    return new TargetRequest("boundary", value, "URL", "test authorization", "80", false,
        null, null, 519L);
  }

  @Test
  void createRejectsExplicitZeroAndOutOfRangePortsBeforePersistence() {
    for (String port : List.of("0", "00000", "65536", "99999")) {
      assertThatThrownBy(() -> service.create(request("http://192.168.222.157:" + port + "/")))
          .isInstanceOf(ApiException.class).hasMessage("URL 端口必须在 1-65535 范围内");
    }
    verify(repository, never()).save(any());
  }

  @Test
  void updateCannotIntroduceAnInvalidPort() {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(7L);
    target.setTargetValue("http://192.168.222.157/");
    target.setAllowedPorts("80");
    when(repository.findById(7L)).thenReturn(Optional.of(target));
    when(links.findByProjectIdAndTargetId(519L, 7L))
        .thenReturn(Optional.of(new ProjectTarget(519L, 7L)));
    for (String port : List.of("0", "65536", "99999")) {
      assertThatThrownBy(() -> service.update(7L, request("http://192.168.222.157:" + port + "/")))
          .isInstanceOf(ApiException.class).hasMessage("URL 端口必须在 1-65535 范围内");
    }
    verify(repository, never()).save(any());
  }

  @Test
  void omittedDefaultAndValidBoundaryPortsRemainAccepted() {
    for (String suffix : List.of("", ":1", ":80", ":443", ":65535")) {
      service.create(request("http://192.168.222.157" + suffix + "/"));
    }
    verify(repository, times(5)).save(any());
  }
}
