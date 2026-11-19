package com.bachelor.toolbox.recon;
import static org.assertj.core.api.Assertions.assertThat;
import java.util.*;
import org.junit.jupiter.api.Test;
class IcpCaptureCapacityTests {
  @Test void newKeysCannotGrowBeyondFiveHundredEntries() throws Exception {
    var store=new IcpBrowserCaptureStore();
    for(long i=1;i<=600;i++) store.store(1L,i,"example.test",List.of(Map.of("owner","QA")));
    var field=IcpBrowserCaptureStore.class.getDeclaredField("store");field.setAccessible(true);
    assertThat(((Map<?,?>)field.get(store)).size()).isEqualTo(500);
    assertThat(store.take(1L,600L)).isNotNull();
  }
  @Test void replacementDoesNotEvictAnotherEntryAtCapacity() {
    var store=new IcpBrowserCaptureStore();
    for(long i=1;i<=500;i++) store.store(1L,i,"example.test",List.of(Map.of("owner","QA")));
    store.store(1L,500L,"example.test",List.of(Map.of("owner","updated")));
    assertThat(store.take(1L,1L)).isNotNull();
    assertThat(store.take(1L,500L).records().get(0).get("owner")).isEqualTo("updated");
  }
}
