package com.bachelor.toolbox.probe;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.Flow;
import org.junit.jupiter.api.Test;
class ProbeBodySubscriberTests {
 @Test void exactBudgetCompletesAndExcessCancelsSubscription(){
  var subscription=mock(Flow.Subscription.class);var body=new ProbeBodySubscriber(3);body.onSubscribe(subscription);
  body.onNext(List.of(ByteBuffer.wrap(new byte[]{1,2,3})));body.onComplete();
  assertThat(body.getBody().toCompletableFuture().join()).containsExactly((byte)1,(byte)2,(byte)3);
  var excess=new ProbeBodySubscriber(3);var sub=mock(Flow.Subscription.class);excess.onSubscribe(sub);
  excess.onNext(List.of(ByteBuffer.wrap(new byte[]{1,2}),ByteBuffer.wrap(new byte[]{3,4})));
  assertThat(excess.getBody().toCompletableFuture().isCompletedExceptionally()).isTrue();verify(sub).cancel();
 }
}
