package com.bachelor.toolbox.target;

import jakarta.persistence.LockModeType;
import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuthorizedTargetRepository extends JpaRepository<AuthorizedTarget, Long> {
  Page<AuthorizedTarget> findAll(Pageable pageable);

  @Query(
      """
      select target
      from AuthorizedTarget target
      where exists (
        select link.id
        from ProjectTarget link, AssessmentProject project
        where link.targetId = target.id
          and project.id = link.projectId
          and project.owner = :owner
      )
      """)
  Page<AuthorizedTarget> findAccessibleByProjectOwner(
      @Param("owner") String owner, Pageable pageable);

  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query("select target from AuthorizedTarget target where target.id = :id")
  Optional<AuthorizedTarget> findByIdForUpdate(@Param("id") Long id);
}
