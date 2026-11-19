package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.Test;

class IcpCaptureSnapshotTests {
  @Test void inputMutationCannotChangeSavedCanonicalRecords() {
    IcpBrowserCaptureStore store = new IcpBrowserCaptureStore();
    Map<String,Object> row = new LinkedHashMap<>(); row.put("owner", "original");
    List<Map<String,Object>> rows = new ArrayList<>(); rows.add(row);
    store.store(1L,2L,"example.test",rows);
    row.put("owner","changed"); rows.clear();
    assertThat(store.take(1L,2L).records()).hasSize(1);
    assertThat(store.take(1L,2L).records().get(0).get("owner")).isEqualTo("original");
  }
  @Test void returnedSnapshotCannotBeModified() {
    IcpBrowserCaptureStore store = new IcpBrowserCaptureStore();
    store.store(1L,2L,"example.test",new ArrayList<>(List.of(new LinkedHashMap<>(Map.of("owner","original")))));
    var records=store.take(1L,2L).records();
    assertThatThrownBy(()->records.clear()).isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(()->records.get(0).put("owner","changed")).isInstanceOf(UnsupportedOperationException.class);
    assertThat(store.take(1L,3L)).isNull();
    store.clear(1L,2L); assertThat(store.take(1L,2L)).isNull();
  }
}
