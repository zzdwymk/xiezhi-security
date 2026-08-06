package com.bachelor.toolbox.target;

import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/targets")
public class TargetController {
  private final TargetService service;

  public TargetController(TargetService service) {
    this.service = service;
  }

  @GetMapping
  public List<AuthorizedTarget> list() {
    return service.list();
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  public AuthorizedTarget create(@Valid @RequestBody TargetRequest request) {
    return service.create(request);
  }

  @PutMapping("/{id}")
  public AuthorizedTarget update(@PathVariable Long id, @Valid @RequestBody TargetRequest request) {
    return service.update(id, request);
  }

  @DeleteMapping("/{id}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void delete(@PathVariable Long id) {
    service.delete(id);
  }
}
