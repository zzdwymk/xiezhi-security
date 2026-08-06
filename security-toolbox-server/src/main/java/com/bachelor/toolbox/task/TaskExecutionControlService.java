package com.bachelor.toolbox.task;

import com.bachelor.toolbox.common.ApiException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class TaskExecutionControlService {
  private final Semaphore global;
  private final int globalLimit;
  private final int perTargetLimit;
  private final ConcurrentHashMap<Long, Semaphore> targets = new ConcurrentHashMap<>();
  private final Set<Long> cancellations = ConcurrentHashMap.newKeySet();
  private final ConcurrentHashMap<Long, Thread> workers = new ConcurrentHashMap<>();

  public TaskExecutionControlService(
      @Value("${toolbox.execution.max-concurrent-tasks:3}") int globalLimit,
      @Value("${toolbox.execution.max-concurrent-tasks-per-target:1}") int perTargetLimit) {
    this.globalLimit = Math.max(1, globalLimit);
    global = new Semaphore(this.globalLimit, true);
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

  public void clear(Long taskId) {
    cancellations.remove(taskId);
    workers.remove(taskId);
  }

  public int maxConcurrentTasks() {
    return globalLimit;
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
