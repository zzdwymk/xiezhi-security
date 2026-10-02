package com.bachelor.toolbox.operation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.auth.DefaultAdminInitializer;
import com.bachelor.toolbox.auth.User;
import com.bachelor.toolbox.auth.UserRepository;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.traffic.MitmCertificateAuthority;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@DataJpaTest(showSql = false)
class SecurityActionAdministratorIntegrationTests {
  @Autowired private UserRepository users;
  @Autowired private SecurityActionRepository actions;
  private SecurityActionService service;

  @BeforeEach
  @SuppressWarnings("unchecked")
  void initializeRealAccounts() {
    users.deleteAll();
    ObjectProvider<MitmCertificateAuthority> certificates = mock(ObjectProvider.class);
    new DefaultAdminInitializer(users, new BCryptPasswordEncoder(4), "test-initial-admin-password",
        false, false, false, false, certificates).run(null);
    users.flush();
    service = new SecurityActionService(actions, mock(AssessmentProjectService.class),
        mock(TargetService.class), mock(AuditService.class), users);
  }

  @Test
  void initializedServiceAccountAndNonReviewersDoNotDisableSingleAdministratorMode() {
    assertThat(users.count()).isEqualTo(2);
    User agent = users.findByUsername("ai-agent").orElseThrow();
    assertThat(agent.isEnabled()).isFalse();
    assertThat(agent.getRole()).isEqualTo("AI_AGENT");
    assertThat(users.countByRoleAndEnabledTrue("ADMIN")).isEqualTo(1);
    addUser("disabled-reviewer", "ADMIN", false);
    addUser("ordinary-member", "USER", true);
    assertThat(users.countByRoleAndEnabledTrue("ADMIN")).isEqualTo(1);

    SecurityAction action = pendingAction();
    service.decide(1L, action.getId(), new SecurityActionDtos.Decision("APPROVED", "人工确认"), admin("admin"));
    actions.flush();
    assertThat(actions.findById(action.getId()).orElseThrow().getStatus()).isEqualTo("APPROVED");
    assertThat(action.getApprovedBy()).isEqualTo("admin");
  }

  @Test
  void secondEnabledAdministratorRequiresIndependentReviewerAfterRealInitialization() {
    addUser("reviewer", "ADMIN", true);
    assertThat(users.countByRoleAndEnabledTrue("ADMIN")).isEqualTo(2);
    SecurityAction action = pendingAction();

    assertThatThrownBy(() -> service.decide(1L, action.getId(),
        new SecurityActionDtos.Decision("APPROVED", "本人确认"), admin("admin")))
        .isInstanceOf(ApiException.class).hasMessage("申请人与审批人必须分离");
    assertThat(action.getStatus()).isEqualTo("PENDING_APPROVAL");
    service.decide(1L, action.getId(), new SecurityActionDtos.Decision("APPROVED", "独立复核"), admin("reviewer"));
    assertThat(action.getStatus()).isEqualTo("APPROVED");
    assertThat(action.getApprovedBy()).isEqualTo("reviewer");
  }

  private void addUser(String name, String role, boolean enabled) {
    User user = new User();
    user.setUsername(name);
    user.setRole(role);
    user.setEnabled(enabled);
    user.setPasswordHash("unused-test-fixture-hash");
    users.saveAndFlush(user);
  }

  private SecurityAction pendingAction() {
    SecurityAction action = new SecurityAction();
    action.setProjectId(1L);
    action.setTargetId(7L);
    action.setCategory("VULNERABILITY_VALIDATION");
    action.setTitle("人工记录审批测试");
    action.setPurpose("验证审批身份计数");
    action.setRiskLevel("MEDIUM");
    action.setExecutionPlan("人工复核已登记证据");
    action.setRollbackPlan("结束人工复核");
    action.setWindowStart(Instant.now().minusSeconds(60));
    action.setWindowEnd(Instant.now().plusSeconds(60));
    action.setRequestedBy("admin");
    return actions.saveAndFlush(action);
  }

  private UsernamePasswordAuthenticationToken admin(String name) {
    return new UsernamePasswordAuthenticationToken(name, null,
        List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
  }
}
