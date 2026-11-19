package com.bachelor.toolbox.recon;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;
import com.bachelor.toolbox.asset.DiscoveredPathService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import org.junit.jupiter.api.Test;
class ReconControllerAuthorizationBoundaryTests {
  @Test void everyEndpointRejectsBeforeReadingOrCollectingData() {
    var service=mock(ReconService.class);var paths=mock(DiscoveredPathService.class);
    var auth=mock(ProjectAuthorizationService.class);
    when(auth.requireAccess(7L)).thenThrow(new ApiException("无权访问该评估项目"));
    var controller=new ReconController(service,paths,auth);
    assertThatThrownBy(()->controller.results(7L,null)).isInstanceOf(ApiException.class);
    assertThatThrownBy(()->controller.results(7L,8L)).isInstanceOf(ApiException.class);
    assertThatThrownBy(()->controller.paths(7L,null)).isInstanceOf(ApiException.class);
    assertThatThrownBy(()->controller.paths(7L,8L)).isInstanceOf(ApiException.class);
    assertThatThrownBy(()->controller.collect(7L,null)).isInstanceOf(ApiException.class);
    assertThatThrownBy(()->controller.icpBatch(7L,null)).isInstanceOf(ApiException.class);
    verifyNoInteractions(service,paths);
    verify(auth,times(6)).requireAccess(7L);
  }
  @Test void authorizedReadsKeepProjectAndTargetArguments() {
    var service=mock(ReconService.class);var paths=mock(DiscoveredPathService.class);
    var auth=mock(ProjectAuthorizationService.class);
    var controller=new ReconController(service,paths,auth);
    controller.results(7L,8L);controller.paths(7L,8L);
    verify(service).history(7L,8L);verify(paths).list(7L,8L);
    verify(auth,times(2)).requireAccess(7L);
  }
}
