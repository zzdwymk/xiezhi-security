package com.bachelor.toolbox.ai;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AiConversationSessionRepository
    extends JpaRepository<AiConversationSessionRecord, String> {
  List<AiConversationSessionRecord> findByLastAccessBefore(Instant threshold);

  Optional<AiConversationSessionRecord> findFirstByOrderByLastAccessAsc();
}
