package com.bachelor.toolbox.schedule;

import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/scan-schedules")
public class ScanScheduleController {
  private final ScanScheduleService service;

  public ScanScheduleController(ScanScheduleService service) {
    this.service = service;
  }

  @GetMapping
  public List<ScanSchedule> list() {
    return service.list();
  }

  @GetMapping("/{id}")
  public ScanSchedule get(@PathVariable Long id) {
    return service.get(id);
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  public ScanSchedule create(@Valid @RequestBody CreateScheduleRequest request) {
    return service.create(request);
  }

  @PostMapping("/{id}/enable")
  public ScanSchedule enable(@PathVariable Long id) {
    return service.toggle(id, true);
  }

  @PostMapping("/{id}/disable")
  public ScanSchedule disable(@PathVariable Long id) {
    return service.toggle(id, false);
  }

  @DeleteMapping("/{id}")
  public void delete(@PathVariable Long id) {
    service.delete(id);
  }
}
