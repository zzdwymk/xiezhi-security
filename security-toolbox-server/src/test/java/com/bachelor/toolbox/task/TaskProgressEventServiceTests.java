package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

class TaskProgressEventServiceTests {
  @Test
  void createsStreamForRunningTaskAndAcceptsProgressEvents() {
    TaskProgressEventService service = new TaskProgressEventService();
    SecurityTask task = new SecurityTask();
    task.setId(7L);
    task.setStatus("RUNNING");
    task.setProgress(40);

    SseEmitter emitter = service.subscribe(task);
    service.publish(task, "执行命令：nmap --version");

    assertThat(emitter).isNotNull();
    assertThat(emitter.getTimeout()).isEqualTo(30L * 60L * 1000L);
  }

  @Test
  void createsCompletedSnapshotStreamForTerminalTask() {
    TaskProgressEventService service = new TaskProgressEventService();
    SecurityTask task = new SecurityTask();
    task.setId(8L);
    task.setStatus("SUCCESS");
    task.setProgress(100);

    assertThat(service.subscribe(task)).isNotNull();
  }
}
