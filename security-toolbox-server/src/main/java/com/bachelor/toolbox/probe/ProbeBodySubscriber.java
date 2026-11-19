package com.bachelor.toolbox.probe;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;

/** Limits received bytes before accumulation, including unknown-length/chunked bodies. */
final class ProbeBodySubscriber implements HttpResponse.BodySubscriber<byte[]> {
  private final int limit;
  private final ByteArrayOutputStream output = new ByteArrayOutputStream();
  private final CompletableFuture<byte[]> body = new CompletableFuture<>();
  private Flow.Subscription subscription;
  ProbeBodySubscriber(int limit) { this.limit = limit; }
  public CompletionStage<byte[]> getBody() { return body; }
  public void onSubscribe(Flow.Subscription next) {
    if (subscription != null) { next.cancel(); return; }
    subscription = next; next.request(1);
  }
  public void onNext(List<ByteBuffer> buffers) {
    if (body.isDone()) return;
    for (ByteBuffer buffer : buffers) {
      if (buffer.remaining() > limit - output.size()) {
        subscription.cancel(); body.completeExceptionally(new IOException("探针响应体超过允许大小")); return;
      }
      byte[] bytes = new byte[buffer.remaining()]; buffer.get(bytes); output.writeBytes(bytes);
    }
    subscription.request(1);
  }
  public void onError(Throwable error) { body.completeExceptionally(error); }
  public void onComplete() { body.complete(output.toByteArray()); }
}
