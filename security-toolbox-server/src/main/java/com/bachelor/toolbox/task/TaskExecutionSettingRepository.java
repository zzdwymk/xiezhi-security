package com.bachelor.toolbox.task;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TaskExecutionSettingRepository
    extends JpaRepository<TaskExecutionSetting, Long> {
  Optional<TaskExecutionSetting> findTopByOrderByIdAsc();
}