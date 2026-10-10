package com.bachelor.toolbox.task;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class TaskControllerRetryTests {
  private final TaskService service = mock(TaskService.class);
  private final TaskProgressEventService events = mock(TaskProgressEventService.class);
  private final TaskController controller = new TaskController(service, events,
      mock(TaskControlStatusService.class), mock(TaskExecutionLimitService.class));

  @Test
  void headerReachesTheIdempotentServiceAndResponseUsesCommittedQueueState() throws Exception {
    SecurityTask initiallyPending = task("PENDING", "等待队列");
    SecurityTask committed = task("REJECTED", "本地任务队列已满");
    when(service.retry(7L, "request-key")).thenReturn(initiallyPending);
    when(service.get(8L)).thenReturn(committed);
    MockMvcBuilders.standaloneSetup(controller).build()
        .perform(post("/api/tasks/7/retry").header("Idempotency-Key", "request-key"))
        .andExpect(status().isAccepted()).andExpect(jsonPath("id").value(8))
        .andExpect(jsonPath("status").value("REJECTED"));
    verify(events).publish(committed, "本地任务队列已满");
  }

  @Test
  void oldClientsWithoutTheHeaderKeepTheManualRetryEndpoint() throws Exception {
    SecurityTask pending = task("PENDING", "等待队列");
    when(service.retry(7L)).thenReturn(pending);
    MockMvcBuilders.standaloneSetup(controller).build().perform(post("/api/tasks/7/retry"))
        .andExpect(status().isAccepted()).andExpect(jsonPath("id").value(8));
    verify(service).retry(7L);
  }

  private static SecurityTask task(String status, String message) {
    var task = new SecurityTask();
    task.setId(8L);
    task.setStatus(status);
    task.setProgressMessage(message);
    return task;
  }
}
