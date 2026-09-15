package com.bachelor.toolbox.task;

import com.bachelor.toolbox.common.ApiException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class TaskExecutionControlService {
  private final Semaphore global;
  private final int perTargetLimit;
  private final ConcurrentHashMap<Long, Semaphore> targets = new ConcurrentHashMap<>();
  private final Set<Long> cancellations = ConcurrentHashMap.newKeySet();
  private final ConcurrentHashMap<Long, Thread> workers = new ConcurrentHashMap<>();
  private final AtomicInteger maxConcurrentTasks;

  public TaskExecutionControlService(
      @Value("${toolbox.execution.max-concurrent-tasks:3}") int globalLimit,
      @Value("${toolbox.execution.max-concurrent-tasks-per-target:1}") int perTargetLimit) {
    int initial = Math.max(TaskExecutionSetting.MAX_CONCURRENT_LOWER_BOUND, globalLimit);
    this.maxConcurrentTasks = new AtomicInteger(initial);
    this.global = new Semaphore(initial, true);
    this.perTargetLimit = Math.max(1, perTargetLimit);
  }

  public Permit acquire(Long taskId, Long targetId) {
    if (isCancellationRequested(taskId)) throw new ApiException("任务已取消");
    Semaphore target =
        targets.computeIfAbsent(targetId, ignored -> new Semaphore(perTargetLimit, true));
    boolean globalAcquired = false;
    boolean targetAcquired = false;
    boolean handedOff = false;
    try {
      global.acquire();
      globalAcquired = true;
      target.acquire();
      targetAcquired = true;
      if (isCancellationRequested(taskId)) throw new ApiException("任务已取消");
      handedOff = true;
      return new Permit(global, target);
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
      throw new ApiException("任务等待并发配额时被中断");
    } catch (RuntimeException ex) {
      throw ex;
    } finally {
      if (!handedOff) {
        if (targetAcquired) target.release();
        if (globalAcquired) global.release();
      }
    }
  }

  public void requestCancellation(Long taskId) {
    cancellations.add(taskId);
    Thread worker = workers.get(taskId);
    if (worker != null) worker.interrupt();
  }

  public boolean isCancellationRequested(Long taskId) {
    return cancellations.contains(taskId);
  }

  public void registerWorker(Long taskId, Thread worker) {
    workers.put(taskId, worker);
    if (isCancellationRequested(taskId)) worker.interrupt();
  }

  public void unregisterWorker(Long taskId) {
    workers.remove(taskId);
  }

  /**
   * True only when a live worker thread is still registered for the task. A RUNNING task whose
   * worker is gone (e.g. the executor process was killed before it could write a terminal state) is
   * a zombie and can be safely reaped.
   */
  public boolean hasActiveWorker(Long taskId) {
    Thread worker = workers.get(taskId);
    return worker != null && worker.isAlive();
  }

  public void clear(Long taskId) {
    cancellations.remove(taskId);
    workers.remove(taskId);
  }

  /**
   * Dynamically changes the global concurrency cap. Increasing adds permits immediately; decreasing
   * drains only the currently free permits so in-flight tasks are never interrupted. Because of
   * that, after a shrink the effective cap may settle to the new value as busy tasks finish.
   */
  public synchronized void resizeMaxConcurrentTasks(int newLimit) {
    int bounded = Math.max(
        TaskExecutionSetting.MAX_CONCURRENT_LOWER_BOUND,
        Math.min(TaskExecutionSetting.MAX_CONCURRENT_UPPER_BOUND, newLimit));
    int previous = maxConcurrentTasks.getAndSet(bounded);
    int delta = bounded - previous;
    if (delta > 0) {
      global.release(delta);
    } else if (delta < 0) {
      int toRemove = -delta;
      for (int i = 0; i < toRemove; i++) {
        if (!global.tryAcquire()) break;
      }
    }
  }

  public int maxConcurrentTasks() {
    return maxConcurrentTasks.get();
  }

  public int availableConcurrentSlots() {
    return global.availablePermits();
  }

  public int maxConcurrentTasksPerTarget() {
    return perTargetLimit;
  }

  public static final class Permit implements AutoCloseable {
    private final Semaphore global;
    private final Semaphore target;
    private boolean closed;

    private Permit(Semaphore global, Semaphore target) {
      this.global = global;
      this.target = target;
    }

    @Override
    public void close() {
      if (!closed) {
        closed = true;
        target.release();
        global.release();
      }
    }
  }
}