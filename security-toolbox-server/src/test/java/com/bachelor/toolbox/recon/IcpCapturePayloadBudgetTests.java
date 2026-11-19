package com.bachelor.toolbox.recon;
import static org.assertj.core.api.Assertions.*;
import com.bachelor.toolbox.common.ApiException;
import java.util.*;
import org.junit.jupiter.api.Test;
class IcpCapturePayloadBudgetTests {
  @Test void tooManyRowsAreRejectedWithoutReplacingSavedRecords() {
    var store=new IcpBrowserCaptureStore();
    store.store(1L,2L,"example.test",List.of(Map.of("owner","original")));
    var rows=Collections.nCopies(501,Map.<String,Object>of("owner","QA"));
    assertThatThrownBy(()->store.store(1L,2L,"example.test",rows)).isInstanceOf(ApiException.class);
    assertThat(store.take(1L,2L).records().get(0).get("owner")).isEqualTo("original");
  }
  @Test void hugeFieldsAndNonScalarValuesCannotEnterTheCache() {
    var store=new IcpBrowserCaptureStore();
    assertThatThrownBy(()->store.store(1L,2L,"example.test",List.of(Map.of("owner","a".repeat(2049))))).isInstanceOf(ApiException.class);
    assertThatThrownBy(()->store.store(1L,2L,"example.test",List.of(Map.of("owner",new ArrayList<>())))).isInstanceOf(ApiException.class);
    assertThat(store.take(1L,2L)).isNull();
  }
  @Test void totalTextBudgetIsEnforcedEvenWhenEveryFieldIsSmall() {
    var store=new IcpBrowserCaptureStore();
    var rows=Collections.nCopies(500,Map.<String,Object>of("owner","a".repeat(1000)));
    assertThatThrownBy(()->store.store(1L,2L,"example.test",rows)).isInstanceOf(ApiException.class);
  }
  @Test void ordinaryCanonicalRowsAndNullScalarRemainSupported() {
    var store=new IcpBrowserCaptureStore();
    Map<String,Object> row=new LinkedHashMap<>();row.put("owner","QA");row.put("type",null);
    store.store(1L,2L,"example.test",List.of(row));
    assertThat(store.take(1L,2L).records()).hasSize(1);
  }
}
