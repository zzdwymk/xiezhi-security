package com.bachelor.toolbox.project;

import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AssessmentProjectRepository extends JpaRepository<AssessmentProject, Long> {
  List<AssessmentProject> findByOwner(String owner);

  Page<AssessmentProject> findByOwner(String owner, Pageable pageable);
}
