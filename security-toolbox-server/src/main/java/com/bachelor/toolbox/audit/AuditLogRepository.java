package com.bachelor.toolbox.audit;

import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
  List<AuditLog> findTop100ByOrderByCreatedAtDesc();

  List<AuditLog> findTop100ByResourceTypeAndResourceIdOrderByCreatedAtDesc(
      String resourceType, String resourceId);

  long countByResourceTypeAndResourceId(String resourceType, String resourceId);

  Page<AuditLog> findAllByOrderByCreatedAtDesc(Pageable pageable);

  @Query(
      """
      select audit from AuditLog audit
      where (audit.resourceType = 'PROJECT' and audit.resourceId = :projectIdText)
         or audit.relatedTaskId in (
              select task.id from SecurityTask task where task.projectId = :projectId
         )
      order by audit.createdAt desc
      """)
  Page<AuditLog> findByProjectId(
      @Param("projectId") Long projectId,
      @Param("projectIdText") String projectIdText,
      Pageable pageable);
}
