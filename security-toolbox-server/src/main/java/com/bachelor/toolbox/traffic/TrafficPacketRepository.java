package com.bachelor.toolbox.traffic;

import java.util.List;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import jakarta.persistence.LockModeType;

public interface TrafficPacketRepository extends JpaRepository<TrafficPacket, Long> {
  List<TrafficPacket> findAllBySessionIdOrderByCreatedAtDesc(Long sessionId);

  List<TrafficPacket> findAllBySessionIdOrderByCreatedAtDescIdDesc(
      Long sessionId, Pageable pageable);

  @Lock(LockModeType.PESSIMISTIC_WRITE)
  List<TrafficPacket> findAllByMarkedFalseOrderByIdAsc(Pageable pageable);

  long countBySessionId(Long sessionId);

  /** 某会话按 id 升序（最旧在前）分页，用于保留上限淘汰（Round 23）。 */
  List<TrafficPacket> findAllBySessionIdOrderByIdAsc(Long sessionId, Pageable pageable);

  /** 代理观测到的某主机去重路径（含查询串）。用于被动子路径聚合。 */
  @Query(
      "select distinct p.scheme, p.host, p.port, p.path from TrafficPacket p"
          + " where lower(p.host) = lower(:host)")
  List<Object[]> findDistinctEndpointsByHost(@Param("host") String host);
}
