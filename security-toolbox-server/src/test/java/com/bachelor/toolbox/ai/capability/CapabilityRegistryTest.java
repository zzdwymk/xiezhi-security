package com.bachelor.toolbox.ai.capability;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bachelor.toolbox.common.ApiException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** {@link CapabilityRegistry} 的注册、查询与黑名单语义。 */
class CapabilityRegistryTest {

  private static AgentCapability capability(String code) {
    return new StubCapability(code);
  }

  @Test
  void registersAndFindsByCode() {
    AgentCapability nmap = capability("nmap_service_scan");
    CapabilityRegistry registry = new CapabilityRegistry(List.of(nmap, capability("tcp_ports")));

    assertSame(nmap, registry.require("nmap_service_scan"));
    assertTrue(registry.find("tcp_ports").isPresent());
    assertEquals(2, registry.size());
  }

  @Test
  void findReturnsEmptyForUnknownCodeInsteadOfThrowing() {
    CapabilityRegistry registry = new CapabilityRegistry(List.of(capability("tcp_ports")));

    assertTrue(registry.find("does_not_exist").isEmpty());
    assertTrue(registry.find(null).isEmpty());
  }

  @Test
  void requireThrowsForUnknownCode() {
    CapabilityRegistry registry = new CapabilityRegistry(List.of(capability("tcp_ports")));

    ApiException error = assertThrows(ApiException.class, () -> registry.require("nope"));
    assertTrue(error.getMessage().contains("nope"));
  }

  @Test
  void listsAllCapabilitiesInRegistrationOrder() {
    CapabilityRegistry registry =
        new CapabilityRegistry(List.of(capability("a"), capability("b"), capability("c")));

    assertEquals(List.of("a", "b", "c"), registry.all().stream().map(AgentCapability::code).toList());
  }

  @Test
  void rejectsDuplicateCode() {
    CapabilityRegistry registry = new CapabilityRegistry(List.of(capability("tcp_ports")));

    IllegalStateException error =
        assertThrows(IllegalStateException.class, () -> registry.register(capability("tcp_ports")));
    assertTrue(error.getMessage().contains("tcp_ports"));
  }

  @Test
  void rejectsBlankCode() {
    CapabilityRegistry registry = new CapabilityRegistry(List.of());

    assertThrows(IllegalStateException.class, () -> registry.register(capability("  ")));
    assertThrows(IllegalStateException.class, () -> registry.register(capability(null)));
  }

  @Test
  void acceptsNullCapabilityList() {
    CapabilityRegistry registry = new CapabilityRegistry(null, null);

    assertEquals(0, registry.size());
    assertTrue(registry.all().isEmpty());
  }

  // ------------------------------------------------------------------ 黑名单

  @Test
  void blacklistIsQueriedByCodeAndByCapability() {
    AgentCapability blocked = capability("system_shutdown");
    CapabilityRegistry registry =
        new CapabilityRegistry(List.of(blocked, capability("tcp_ports")), Set.of("system_shutdown"));

    assertTrue(registry.isBlocked("system_shutdown"));
    assertTrue(registry.isBlocked(blocked));
    assertFalse(registry.isBlocked("tcp_ports"));
    assertEquals(Set.of("system_shutdown"), registry.blockedCodes());
  }

  @Test
  void blacklistIsEmptyByDefaultSoNothingIsBlocked() {
    CapabilityRegistry registry = new CapabilityRegistry(List.of(capability("tcp_ports")));

    assertFalse(registry.isBlocked("tcp_ports"));
    assertTrue(registry.blockedCodes().isEmpty());
  }

  @Test
  void blacklistIgnoresNullAndBlankEntries() {
    CapabilityRegistry registry =
        new CapabilityRegistry(List.of(capability("tcp_ports")), Set.of("  ", "system_shutdown"));

    assertEquals(Set.of("system_shutdown"), registry.blockedCodes());
    assertFalse(registry.isBlocked((String) null));
    assertFalse(registry.isBlocked((AgentCapability) null));
  }

  @Test
  void blockedCodesSnapshotIsReadOnly() {
    CapabilityRegistry registry =
        new CapabilityRegistry(List.of(capability("system_shutdown")), Set.of("system_shutdown"));

    assertThrows(
        UnsupportedOperationException.class, () -> registry.blockedCodes().add("tcp_ports"));
  }

  @Test
  void allSnapshotIsReadOnly() {
    CapabilityRegistry registry = new CapabilityRegistry(List.of(capability("tcp_ports")));

    assertThrows(
        UnsupportedOperationException.class, () -> registry.all().add(capability("extra")));
  }

  /** 只关心 code 的最小能力实现。 */
  private static final class StubCapability implements AgentCapability {
    private final String code;

    private StubCapability(String code) {
      this.code = code;
    }

    @Override
    public String code() {
      return code;
    }

    @Override
    public String displayName() {
      return code;
    }

    @Override
    public String description() {
      return code;
    }

    @Override
    public Map<String, Object> parameterSchema() {
      return Map.of();
    }

    @Override
    public CapabilityKind kind() {
      return CapabilityKind.READ;
    }

    @Override
    public RiskLevel risk() {
      return RiskLevel.SAFE;
    }

    @Override
    public boolean requiresApproval() {
      return false;
    }
  }
}
