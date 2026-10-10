package com.bachelor.toolbox.audit;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class AuditRequestContextTests {
  private final ExecutorService worker = Executors.newSingleThreadExecutor();

  @AfterEach
  void cleanUp() throws InterruptedException {
    AuditRequestContext.clear();
    worker.shutdownNow();
    assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS));
  }

  @Test
  void queuedTaskKeepsRequestMetadataAfterFilterReturnsAndClearsWorker() throws Exception {
    var request = new MockHttpServletRequest();
    request.setRemoteAddr("192.0.2.10");
    var response = new MockHttpServletResponse();
    var queued = new AtomicReference<Runnable>();
    var observed = new AtomicReference<AuditRequestContext.RequestMetadata>();
    new AuditRequestContextFilter().doFilter(
        request, response,
        (req, res) -> queued.set(AuditRequestContext.wrap(() -> observed.set(AuditRequestContext.get()))));
    assertNull(AuditRequestContext.get());

    worker.submit(queued.get()).get(5, TimeUnit.SECONDS);

    assertEquals(response.getHeader(AuditRequestContextFilter.REQUEST_ID_HEADER), observed.get().requestId());
    assertEquals("192.0.2.10", observed.get().sourceIp());
    assertNull(worker.submit(AuditRequestContext::get).get(5, TimeUnit.SECONDS));
  }

  @Test
  void taskFailureRestoresPreviousWorkerMetadata() throws Exception {
    AuditRequestContext.set("request", "192.0.2.10");
    Runnable wrapped = AuditRequestContext.wrap(() -> {
      assertEquals("request", AuditRequestContext.get().requestId());
      throw new IllegalStateException("scan failed");
    });
    AuditRequestContext.clear();

    worker.submit(() -> {
      AuditRequestContext.set("previous", "127.0.0.1");
      assertThrows(IllegalStateException.class, wrapped::run);
      assertEquals("previous", AuditRequestContext.get().requestId());
      AuditRequestContext.clear();
    }).get(5, TimeUnit.SECONDS);
    assertNull(worker.submit(AuditRequestContext::get).get(5, TimeUnit.SECONDS));
  }

  @Test
  void absentRequestDoesNotBorrowUnrelatedWorkerMetadata() throws Exception {
    Runnable wrapped = AuditRequestContext.wrap(() -> assertNull(AuditRequestContext.get()));

    worker.submit(() -> {
      AuditRequestContext.set("unrelated", "127.0.0.1");
      wrapped.run();
      assertEquals("unrelated", AuditRequestContext.get().requestId());
      AuditRequestContext.clear();
    }).get(5, TimeUnit.SECONDS);
  }

  @Test
  void streamIoFailureRestoresPreviousWorkerMetadata() throws Exception {
    AuditRequestContext.set("stream-request", "192.0.2.11");
    var wrapped = AuditRequestContext.wrapStream(output -> {
      assertEquals("stream-request", AuditRequestContext.get().requestId());
      throw new IOException("client disconnected");
    });
    AuditRequestContext.clear();

    worker.submit(() -> {
      AuditRequestContext.set("previous", "127.0.0.1");
      assertThrows(IOException.class, () -> wrapped.writeTo(new ByteArrayOutputStream()));
      assertEquals("previous", AuditRequestContext.get().requestId());
      AuditRequestContext.clear();
    }).get(5, TimeUnit.SECONDS);
    assertNull(worker.submit(AuditRequestContext::get).get(5, TimeUnit.SECONDS));
  }
}
