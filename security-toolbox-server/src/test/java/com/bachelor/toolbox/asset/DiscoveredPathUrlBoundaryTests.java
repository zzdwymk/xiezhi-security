package com.bachelor.toolbox.asset;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import com.bachelor.toolbox.target.*;
import org.junit.jupiter.api.Test;
class DiscoveredPathUrlBoundaryTests {
  @Test void nonHttpAndCredentialBearingUrlsNeverReachRepository() {
    var repository=mock(DiscoveredPathRepository.class);var policy=mock(TargetPolicyService.class);
    var service=new DiscoveredPathService(repository,policy);var target=new AuthorizedTarget();
    target.setId(2L);target.setTargetValue("http://192.168.222.158");target.setAllowedPorts("80");
    for(String url:new String[]{"ftp://192.168.222.158:80/file","http://user:qa-only@192.168.222.158/path","//192.168.222.158/path"})
      assertThat(service.record(target,1L,url,"QA",null,null,null)).as(url).isFalse();
    verifyNoInteractions(repository);
  }
  @Test void ordinaryHttpAssetRemainsRecordable() {
    var repository=mock(DiscoveredPathRepository.class);var policy=mock(TargetPolicyService.class);
    var service=new DiscoveredPathService(repository,policy);var target=new AuthorizedTarget();
    target.setId(2L);target.setTargetValue("http://192.168.222.158");target.setAllowedPorts("80");
    assertThat(service.record(target,1L,"http://192.168.222.158/path","QA",200,10L,null)).isTrue();
    verify(repository).save(any(DiscoveredPath.class));
  }
}
