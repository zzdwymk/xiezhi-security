package com.bachelor.toolbox.report;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.*;
import com.bachelor.toolbox.task.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Pageable;
class ReportFindingAggregateBudgetTests {
 @Test void findingsAcrossTaskBatchesCannotBypassTotalBudget() throws Exception {
  var findings=mock(FindingRepository.class);
  when(findings.findAllByTaskIdIn(anyList(),any(Pageable.class))).thenAnswer(invocation->{
   List<Long> ids=invocation.getArgument(0);Pageable page=invocation.getArgument(1);
   int count=ids.size()>1?15000:5001;int from=(int)page.getOffset();
   if(from>=count)return List.of();return Collections.nCopies(Math.min(page.getPageSize(),count-from),new Finding());
  });
  var service=new ProjectReportSummaryService(null,null,null,findings,null,null,null);
  List<SecurityTask> tasks=new ArrayList<>();for(long i=1;i<=501;i++){var t=new SecurityTask();t.setId(i);tasks.add(t);}
  var method=ProjectReportSummaryService.class.getDeclaredMethod("loadFindings",List.class);method.setAccessible(true);
  assertThatThrownBy(()->method.invoke(service,tasks)).hasCauseInstanceOf(ApiException.class);
 }
}
