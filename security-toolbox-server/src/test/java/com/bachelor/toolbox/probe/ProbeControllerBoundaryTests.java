package com.bachelor.toolbox.probe;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import org.junit.jupiter.api.Test;
class ProbeControllerBoundaryTests {
 @Test void routeProjectOverridesClientSuppliedProjectBeforeDelegation(){
  var service=mock(ProbeService.class);var auth=mock(ProjectAuthorizationService.class);
  var request=new ProbeRequest();request.setProjectId(99L);request.setTargetId(2L);
  new ProbeController(service,auth).probe(1L,request);
  assertThat(request.getProjectId()).isEqualTo(1L);
  var order=inOrder(auth,service);order.verify(auth).requireAccess(1L);order.verify(service).probe(request);
 }
 @Test void deniedProjectCannotExecuteReadOrDelete(){
  var service=mock(ProbeService.class);var auth=mock(ProjectAuthorizationService.class);
  when(auth.requireAccess(1L)).thenThrow(new ApiException("无权访问该评估项目"));
  var controller=new ProbeController(service,auth);
  assertThatThrownBy(()->controller.probe(1L,new ProbeRequest())).isInstanceOf(ApiException.class);
  assertThatThrownBy(()->controller.history(1L,null)).isInstanceOf(ApiException.class);
  assertThatThrownBy(()->controller.history(1L,2L)).isInstanceOf(ApiException.class);
  assertThatThrownBy(()->controller.delete(1L,3L)).isInstanceOf(ApiException.class);
  verifyNoInteractions(service);
 }
}
