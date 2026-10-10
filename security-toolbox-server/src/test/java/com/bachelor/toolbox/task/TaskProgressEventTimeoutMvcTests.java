package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.bachelor.toolbox.common.GlobalExceptionHandler;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import jakarta.servlet.AsyncEvent;
import java.io.IOException;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockAsyncContext;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.async.AsyncRequestTimeoutException;
import org.springframework.web.context.request.async.DeferredResult;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import org.springframework.web.servlet.mvc.method.annotation.ExceptionHandlerExceptionResolver;
import org.slf4j.LoggerFactory;

class TaskProgressEventTimeoutMvcTests {
  private final TaskProgressEventService events = new TaskProgressEventService();
  private final TaskService tasks = mock(TaskService.class);
  private final SecurityTask task = new SecurityTask();
  private final ListAppender<ILoggingEvent> exceptionHandlerLogs = new ListAppender<>();
  private final Logger exceptionResolverLogger = (Logger) LoggerFactory.getLogger(ExceptionHandlerExceptionResolver.class);
  private MockMvc mvc;

  @BeforeEach
  void setUp() {
    exceptionHandlerLogs.start();
    exceptionResolverLogger.addAppender(exceptionHandlerLogs);
    task.setId(7L);
    task.setStatus("RUNNING");
    task.setProgress(40);
    when(tasks.get(7L)).thenReturn(task);
    mvc = MockMvcBuilders.standaloneSetup(
        new TaskController(tasks, events, mock(TaskControlStatusService.class), mock(TaskExecutionLimitService.class)),
        new TimeoutController())
        .setControllerAdvice(new GlobalExceptionHandler())
        .build();
  }

  @AfterEach
  void noSecondaryExceptionDuringTimeoutHandling() {
    exceptionResolverLogger.detachAppender(exceptionHandlerLogs);
    exceptionHandlerLogs.stop();
    assertThat(exceptionHandlerLogs.list)
        .noneMatch(event -> event.getFormattedMessage().contains("Failure in @ExceptionHandler"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"/api/tasks/7/events", "/api/tasks/events"})
  void taskStreamTimeoutCompletesMvcWithoutJsonAndRetiresOnlyExpiredSubscription(String path) throws Exception {
    MvcResult expired = mvc.perform(get(path).accept(MediaType.TEXT_EVENT_STREAM))
        .andExpect(status().isOk())
        .andExpect(request().asyncStarted())
        .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_EVENT_STREAM))
        .andReturn();
    assertThat(expired.getResponse().isCommitted()).isTrue();
    String initialBody = expired.getResponse().getContentAsString();
    assertThat(initialBody).contains(path.contains("/7/") ? "event:snapshot" : "event:ready");
    assertThat(subscriberCount()).isEqualTo(1);

    MockAsyncContext oldContext = fireTimeout(expired);

    assertThat(expired.getAsyncResult(1_000)).isNull();
    assertThat(subscriberCount()).isZero();
    mvc.perform(asyncDispatch(expired))
        .andExpect(status().isOk())
        .andExpect(request().asyncNotStarted())
        .andExpect(content().string(initialBody));

    MvcResult reconnected = mvc.perform(get(path).accept(MediaType.TEXT_EVENT_STREAM))
        .andExpect(request().asyncStarted()).andReturn();
    oldContext.complete();
    assertThat(subscriberCount()).isEqualTo(1);
    events.publish(task, "连接到期后任务仍在运行");
    assertThat(expired.getResponse().getContentAsString()).isEqualTo(initialBody);
    assertThat(reconnected.getResponse().getContentAsString()).contains("event:progress");
    assertThat(task.getStatus()).isEqualTo("RUNNING");
    assertThat(task.getProgress()).isEqualTo(40);
    if (path.contains("/7/")) verify(tasks, org.mockito.Mockito.times(2)).get(7L);
    verifyNoMoreInteractions(tasks);

    MockAsyncContext newContext = fireTimeout(reconnected);
    mvc.perform(asyncDispatch(reconnected)).andExpect(status().isOk());
    newContext.complete();
    assertThat(subscriberCount()).isZero();
  }

  @Test
  void genericAsyncTimeoutOnCommittedEventStreamNeverRunsJsonConversion() throws Exception {
    MvcResult stream = mvc.perform(get("/timeout/stream").accept(MediaType.TEXT_EVENT_STREAM))
        .andExpect(request().asyncStarted()).andReturn();
    String initialBody = stream.getResponse().getContentAsString();
    MockAsyncContext context = fireTimeout(stream);
    assertThat(stream.getAsyncResult(1_000)).isInstanceOf(AsyncRequestTimeoutException.class);

    MvcResult completed = mvc.perform(asyncDispatch(stream))
        .andExpect(status().isOk())
        .andExpect(request().asyncNotStarted())
        .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_EVENT_STREAM))
        .andExpect(content().string(initialBody)).andReturn();
    assertThat(completed.getResolvedException()).isInstanceOf(AsyncRequestTimeoutException.class);
    context.complete();
  }

  @Test
  void genericAsyncTimeoutBeforeFirstEventReturns503WithoutJsonInEventStream() throws Exception {
    MvcResult stream = mvc.perform(get("/timeout/empty-stream").accept(MediaType.TEXT_EVENT_STREAM))
        .andExpect(request().asyncStarted()).andReturn();
    assertThat(stream.getResponse().isCommitted()).isFalse();
    MockAsyncContext context = fireTimeout(stream);
    assertThat(stream.getAsyncResult(1_000)).isInstanceOf(AsyncRequestTimeoutException.class);

    mvc.perform(asyncDispatch(stream))
        .andExpect(status().isServiceUnavailable())
        .andExpect(request().asyncNotStarted())
        .andExpect(content().string(""));
    context.complete();
  }

  @Test
  void ordinaryAsyncJsonRequestRetains503AndLocalizedApiError() throws Exception {
    MvcResult pending = mvc.perform(get("/timeout/json").accept(MediaType.APPLICATION_JSON))
        .andExpect(request().asyncStarted()).andReturn();
    MockAsyncContext context = fireTimeout(pending);
    assertThat(pending.getAsyncResult(1_000)).isInstanceOf(AsyncRequestTimeoutException.class);

    mvc.perform(asyncDispatch(pending))
        .andExpect(status().isServiceUnavailable())
        .andExpect(request().asyncNotStarted())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath("status").value(503))
        .andExpect(jsonPath("message").value("请求处理超时，请稍后重试"));
    context.complete();
  }

  private MockAsyncContext fireTimeout(MvcResult result) throws IOException {
    MockAsyncContext context = (MockAsyncContext) result.getRequest().getAsyncContext();
    assertThat(context.getListeners()).isNotEmpty();
    AsyncEvent event = new AsyncEvent(context, result.getRequest(), result.getResponse());
    for (var listener : context.getListeners()) listener.onTimeout(event);
    return context;
  }

  @SuppressWarnings("unchecked")
  private int subscriberCount() {
    Map<Long, Set<SseEmitter>> individual =
        (Map<Long, Set<SseEmitter>>) ReflectionTestUtils.getField(events, "subscribers");
    Set<SseEmitter> all = (Set<SseEmitter>) ReflectionTestUtils.getField(events, "allTaskSubscribers");
    return individual.values().stream().mapToInt(Set::size).sum() + all.size();
  }

  @RestController
  static class TimeoutController {
    @GetMapping(value = "/timeout/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    SseEmitter stream() throws IOException {
      SseEmitter emitter = new SseEmitter(1L);
      emitter.send(SseEmitter.event().name("ready").data("connected"));
      return emitter;
    }

    @GetMapping(value = "/timeout/empty-stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    SseEmitter emptyStream() {
      return new SseEmitter(1L);
    }

    @GetMapping(value = "/timeout/json", produces = MediaType.APPLICATION_JSON_VALUE)
    DeferredResult<Map<String, Object>> json() {
      return new DeferredResult<>(1L);
    }
  }
}
