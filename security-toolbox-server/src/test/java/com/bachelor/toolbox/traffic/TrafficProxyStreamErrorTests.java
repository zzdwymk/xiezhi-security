package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

class TrafficProxyStreamErrorTests {
  @Test
  void hidesInternalScanFailureFromSseAndCompletesEmitter() throws Exception {
    String sensitive = "C:/internal/ca-store.p12 password=QA_ONLY_SECRET";
    Class<?> actionType = Class.forName(TrafficProxyController.class.getName() + "$ScanAction");
    Object action = Proxy.newProxyInstance(actionType.getClassLoader(), new Class<?>[] {actionType},
        (proxy, method, args) -> { throw new IOException(sensitive); });
    SseEmitter emitter = mock(SseEmitter.class);
    Method runStream = TrafficProxyController.class.getDeclaredMethod("runStream", SseEmitter.class, actionType);
    runStream.setAccessible(true);
    runStream.invoke(null, emitter, action);

    ArgumentCaptor<SseEmitter.SseEventBuilder> events = ArgumentCaptor.forClass(SseEmitter.SseEventBuilder.class);
    verify(emitter).send(events.capture());
    Object data = events.getValue().build().stream().map(item -> item.getData())
        .filter(value -> value instanceof Map).findFirst().orElseThrow();
    assertThat(data.toString()).contains("error").doesNotContain("internal", "QA_ONLY_SECRET", "password=");
    verify(emitter).complete();
  }
}
