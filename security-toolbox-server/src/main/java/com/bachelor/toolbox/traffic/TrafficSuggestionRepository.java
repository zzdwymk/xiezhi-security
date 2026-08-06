package com.bachelor.toolbox.traffic;

import java.util.Collection;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface TrafficSuggestionRepository extends JpaRepository<TrafficSuggestion, Long> {
  Optional<TrafficSuggestion> findByPacketId(Long packetId);

  boolean existsByPacketId(Long packetId);

  @Modifying(flushAutomatically = true)
  @Query("delete from TrafficSuggestion suggestion where suggestion.packetId in :packetIds")
  int deleteAllByPacketIdIn(@Param("packetIds") Collection<Long> packetIds);
}
