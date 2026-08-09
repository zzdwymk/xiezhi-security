package com.bachelor.toolbox.settings;

import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Supplier;
import org.springframework.stereotype.Component;

/** Prevents business-data writers from crossing an exclusive data reset. */
@Component
public class BusinessDataOperationGate {
  private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);

  public <T> T withMutation(Supplier<T> operation) {
    var readLock = lock.readLock();
    readLock.lock();
    try {
      return operation.get();
    } finally {
      readLock.unlock();
    }
  }

  public void withMutation(Runnable operation) {
    withMutation(
        () -> {
          operation.run();
          return null;
        });
  }

  public <T> T withReset(Supplier<T> operation) {
    var writeLock = lock.writeLock();
    writeLock.lock();
    try {
      return operation.get();
    } finally {
      writeLock.unlock();
    }
  }
}
