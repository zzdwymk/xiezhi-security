package com.bachelor.toolbox.settings;

import com.bachelor.toolbox.common.ApiException;
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

  public <T> T withImmediateReset(Supplier<T> operation) {
    var writeLock = lock.writeLock();
    if (!writeLock.tryLock()) {
      throw new ApiException("系统正在处理业务操作，请稍后重试");
    }
    try {
      return operation.get();
    } finally {
      writeLock.unlock();
    }
  }
}
