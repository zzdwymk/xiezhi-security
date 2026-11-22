package com.bachelor.toolbox.ai;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AiConversationSessionRepository
    extends JpaRepository<AiConversationSessionRecord, String> {
  List<AiConversationSessionRecord> findByLastAccessBefore(Instant threshold);

  Optional<AiConversationSessionRecord> findFirstByOrderByLastAccessAsc();

  List<AiConversationSessionRecord> findAllByOrderByLastAccessDesc();

  /** Round 309：按最近访问时间倒序的分页版本，供列表接口限流使用。 */
  List<AiConversationSessionRecord> findAllByOrderByLastAccessDesc(
      org.springframework.data.domain.Pageable pageable);

  void deleteByProjectIdIn(Collection<Long> projectIds);
}

