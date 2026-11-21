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
  private final AdjustableSemaphore global;
  private final int perTargetLimit;
  private final ConcurrentHashMap<Long, Semaphore> targets = new ConcurrentHashMap<>();
  private final Set<Long> cancellations = ConcurrentHashMap.newKeySet();
  private final ConcurrentHashMap<Long, Thread> workers = new ConcurrentHashMap<>();
  private final AtomicInteger maxConcurrentTasks;

  public TaskExecutionControlService(
      @Value("${toolbox.execution.max-concurrent-tasks:3}") int globalLimit,
      @Value("${toolbox.execution.max-concurrent-tasks-per-target:3}") int perTargetLimit) {
    int initial = Math.max(TaskExecutionSetting.MAX_CONCURRENT_LOWER_BOUND, globalLimit);
    this.maxConcurrentTasks = new AtomicInteger(initial);
    this.global = new AdjustableSemaphore(initial);
    // This is the last-resort cap, not the primary ordering rule. Task grouping already keeps a
    // barrier tool (port sweep, crawler, exploit) alone on the target and only batches light
    // read-only probes together; capping per-target at 1 here would re-serialize that batch and
    // silently defeat the grouping. It still bounds runaway concurrency on one host.
    this.perTargetLimit = Math.max(1, perTargetLimit);
  }

  public Permit acquire(Long taskId, Long targetId) {
    if (isCancellationRequested(taskId)) throw new ApiException("任务已取消");
    boolean globalAcquired = false;
    boolean handedOff = false;
    try {
      global.acquire();
      globalAcquired = true;
      Semaphore acquired = acquireTargetPermit(targetId);
      if (isCancellationRequested(taskId)) {
        releaseTargetPermit(targetId, acquired);
        throw new ApiException("任务已取消");
      }
      handedOff = true;
      return new Permit(global, acquired, () -> releaseTargetPermit(targetId, acquired));
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
      throw new ApiException("任务等待并发配额时被中断");
    } finally {
      if (!handedOff && globalAcquired) global.release();
    }
  }

  /**
   * Round 276：按 target 限流用过的 Semaphore 原先只增不减（{@code targets} 永不移除），
   * 每个出现过的 targetId 都会在长跑进程里永久驻留。这里在「许可全部归还」时把条目从 map 移除，
   * 并用「取得许可后复核仍是当前实例」的重试消除与并发 acquire 的竞态：若条目在等待期间被移除，
   * 就归还许可并在新实例上重试，保证同一 target 的并发上限始终成立。
   */
  private Semaphore acquireTargetPermit(Long targetId) throws InterruptedException {
    while (true) {
      Semaphore candidate =
          targets.computeIfAbsent(targetId, ignored -> new Semaphore(perTargetLimit, true));
      candidate.acquire();
      if (targets.get(targetId) == candidate) return candidate;
      candidate.release();
    }
  }

  /** 归还许可；若该 target 的许可已全部归还，则在同一把 key 锁内原子地移除条目。 */
  private void releaseTargetPermit(Long targetId, Semaphore target) {
    targets.compute(
        targetId,
        (ignored, current) -> {
          target.release();
          if (current != target) return current;
          return target.availablePermits() >= perTargetLimit ? null : target;
        });
  }

  /** 供测试与运维观测：当前仍在跟踪的 target 限流器数量。 */
  int trackedTargets() {
    return targets.size();
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
   * Dynamically changes the global concurrency cap without interrupting active tasks. A reduction
   * may leave a permit debt: releases repay that debt before another task can start.
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
      global.reduce(-delta);
    }
  }

  public int maxConcurrentTasks() {
    return maxConcurrentTasks.get();
  }

  public int availableConcurrentSlots() {
    return Math.max(0, global.availablePermits());
  }

  public int maxConcurrentTasksPerTarget() {
    return perTargetLimit;
  }

  private static final class AdjustableSemaphore extends Semaphore {
    private AdjustableSemaphore(int permits) {
      super(permits, true);
    }

    private void reduce(int permits) {
      super.reducePermits(permits);
    }
  }

  public static final class Permit implements AutoCloseable {
    private final Semaphore global;
    private final Semaphore target;
    private final Runnable targetRelease;
    private boolean closed;

    private Permit(Semaphore global, Semaphore target, Runnable targetRelease) {
      this.global = global;
      this.target = target;
      this.targetRelease = targetRelease;
    }

    @Override
    public synchronized void close() {
      if (!closed) {
        closed = true;
        // Round 276：按 target 归还许可走回调，由服务在归还后按需回收该 target 的限流器。
        if (targetRelease != null) targetRelease.run();
        else target.release();
        global.release();
      }
    }
  }
}
