package com.bachelor.toolbox.asset;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.TargetService;
import org.junit.jupiter.api.Test;
class DiscoveredPathControllerBoundaryTests {
  @Test void deniedTargetIsNeverUsedToReadDiscoveredPaths() {
    var service=mock(DiscoveredPathService.class);var targets=mock(TargetService.class);
    when(targets.get(9L)).thenThrow(new ApiException("无权访问该授权目标"));
    assertThatThrownBy(()->new DiscoveredPathController(service,targets,mock(com.bachelor.toolbox.project.ProjectAuthorizationService.class)).list(9L)).isInstanceOf(ApiException.class);
    verifyNoInteractions(service);
  }
  @Test void allowedTargetIsCheckedBeforeReading() {
    var service=mock(DiscoveredPathService.class);var targets=mock(TargetService.class);
    new DiscoveredPathController(service,targets,mock(com.bachelor.toolbox.project.ProjectAuthorizationService.class)).list(9L);
    var order=inOrder(targets,service);order.verify(targets).get(9L);order.verify(service).listByTarget(9L,java.util.List.of());
  }
}
