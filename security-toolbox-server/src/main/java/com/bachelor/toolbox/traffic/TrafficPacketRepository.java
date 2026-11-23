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

  /**
   * 某授权目标观测到的去重路径。Round 354：按 targetId 过滤，避免同 host 的其它项目目标
   * 互相看到对方抓包路径（跨项目数据泄漏）。
   */
  @Query(
      "select distinct p.scheme, p.host, p.port, p.path from TrafficPacket p"
          + " where p.targetId = :targetId and lower(p.host) = lower(:host)")
  List<Object[]> findDistinctEndpointsByTargetIdAndHost(
      @Param("targetId") Long targetId, @Param("host") String host);
}

