package com.bachelor.toolbox.ai;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Round 233：普通用户清空对话只能删除可访问项目范围，不能调用全局 deleteAll。 */
class AiConversationMemoryServiceClearScopeTests {

  private final AiConversationSessionRepository repository =
      mock(AiConversationSessionRepository.class);
  private final AiConversationMemoryService service =
      new AiConversationMemoryService(20, 200, 120, repository, new ObjectMapper(), null);

  @Test
  void scopedClearOnlyDeletesAccessibleProjects() {
    service.clearPersistedThreadsForProjects(List.of(3L, 7L));
    verify(repository).deleteByProjectIdIn(List.of(3L, 7L));
    verify(repository, org.mockito.Mockito.never()).deleteAll();
  }

  @Test
  void emptyProjectListDoesNothing() {
    service.clearPersistedThreadsForProjects(List.of());
    verifyNoInteractions(repository);
  }
}
