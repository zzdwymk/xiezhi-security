package com.bachelor.toolbox.ai;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AgentWorkflowSpecRepository extends JpaRepository<AgentWorkflowSpec, Long> {
  Optional<AgentWorkflowSpec> findFirstByScopeIdOrderByRevisionDesc(Long scopeId);

  Optional<AgentWorkflowSpec> findByScopeIdAndRevision(Long scopeId, Long revision);

  Optional<AgentWorkflowSpec> findByWorkflowIdAndRevision(String workflowId, Long revision);
}
