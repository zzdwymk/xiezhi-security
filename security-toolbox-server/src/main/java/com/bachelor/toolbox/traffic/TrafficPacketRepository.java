package com.bachelor.toolbox.traffic;

import java.util.List;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import jakarta.persistence.LockModeType;

public interface TrafficPacketRepository extends JpaRepository<TrafficPacket, Long> {
  List<TrafficPacket> findAllBySessionIdOrderByCreatedAtDesc(Long sessionId);

  List<TrafficPacket> findAllBySessionIdOrderByCreatedAtDescIdDesc(
      Long sessionId, Pageable pageable);

  @Lock(LockModeType.PESSIMISTIC_WRITE)
  List<TrafficPacket> findAllByMarkedFalseOrderByIdAsc(Pageable pageable);

  long countBySessionId(Long sessionId);
}
