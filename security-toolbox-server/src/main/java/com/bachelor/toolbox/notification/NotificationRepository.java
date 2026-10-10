package com.bachelor.toolbox.notification;

import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface NotificationRepository extends JpaRepository<SystemNotification, Long> {
  boolean existsByEventKey(String eventKey);

  @Query("select coalesce(max(n.id), 0) from SystemNotification n")
  long currentCursor();

  @Query("""
      select n from SystemNotification n
      where n.id > :after and n.id <= :boundary
        and (:admin = true or (n.adminOnly = false and
          (n.projectId is null or exists
            (select p.id from AssessmentProject p where p.id = n.projectId and p.owner = :username))))
      order by n.id asc
      """)
  List<SystemNotification> findVisibleAfter(
      @Param("after") long after, @Param("boundary") long boundary,
      @Param("admin") boolean admin, @Param("username") String username, Pageable pageable);
}
