package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

/**
 * 第381轮：全局任务事件流必须按项目归属过滤。
 *
 * <p>修复前 {@code GET /api/tasks/events} → {@code subscribeAll()} 会把**所有**任务的进度事件推给
 * **任何已认证用户**，事件负载含 {@code taskId/projectId/targetId/toolCode/progressMessage/errorMessage/logLine}，
 * 即跨项目（跨租户）信息泄露。本测试锁定修复后的过滤契约：
 *
 * <ul>
 *   <li>普通用户订阅只收到自己可访问项目的事件；
 *   <li>管理员（全部项目）仍收到全部事件；
 *   <li>按任务订阅（{@code subscribe(task)}）不受影响。
 * </ul>
 */
@DisplayName("任务事件流按项目过滤（第381轮）")
class TaskProgressEventServiceScopeTests {
  private final List<Map<String, Object>> delivered = new CopyOnWriteArrayList<>();
  private final Map<Long, List<Map<String, Object>>> perTask = new ConcurrentHashMap<>();

  /** 记录发送内容的发射器替身（SseEmitter#send 是 final 友好方法，故继承记录）。 */
  private static final class RecordingEmitter extends SseEmitter {
    private final List<String> events = new CopyOnWriteArrayList<>();

    RecordingEmitter() {
      super(60_000L);
    }

    @Override
    public void send(SseEventBuilder builder) throws IOException {
      // SseEventBuilder 不暴露数据，改为在服务端调用处记录（见下）。
      events.add("event");
    }
  }

  private static SecurityTask task(long id, Long projectId) {
    SecurityTask task = new SecurityTask();
    task.setId(id);
    task.setProjectId(projectId);
    task.setTargetId(9L);
    task.setToolCode("http_headers");
    task.setStatus("RUNNING");
    task.setProgress(10);
    task.setProgressMessage("进行中");
    return task;
  }

  @Test
  @DisplayName("普通用户只收到自己项目的事件，管理员收到全部")
  void nonAdminOnlyReceivesOwnProjectEvents() {
    TaskProgressEventService service = new TaskProgressEventService(ignored -> new RecordingEmitter());

    SseEmitter alice = service.subscribeAll(false, Set.of(1L));
    SseEmitter admin = service.subscribeAll(true, Set.of());
    // 订阅时服务端会先发一条 ready 事件；这里清空，只观察后续 progress 事件的过滤结果。
    recordingOf(alice).clear();
    recordingOf(admin).clear();

    service.publish(task(101L, 1L), "alice-project event");
    service.publish(task(202L, 2L), "other-project event");

    assertThat(recordingOf(alice))
        .as("alice 只应收到项目1的事件")
        .containsExactly("event");
    assertThat(recordingOf(admin))
        .as("admin 应收到两个项目的事件")
        .hasSize(2);
  }

  @Test
  @DisplayName("项目为空的全局订阅者（无可见项目）不会收到任何事件")
  void subscriberWithoutVisibleProjectsReceivesNothing() {
    TaskProgressEventService service = new TaskProgressEventService(ignored -> new RecordingEmitter());
    SseEmitter none = service.subscribeAll(false, Set.of());
    recordingOf(none).clear();
    service.publish(task(303L, 3L), "event");
    assertThat(recordingOf(none)).isEmpty();
  }

  private static List<String> recordingOf(SseEmitter emitter) {
    return ((RecordingEmitter) emitter).events;
  }
}
