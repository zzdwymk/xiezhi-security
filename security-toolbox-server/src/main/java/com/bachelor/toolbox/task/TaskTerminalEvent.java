package com.bachelor.toolbox.task;

/** Internal signal used to unlock or skip workflow successors after a task reaches a terminal state. */
public record TaskTerminalEvent(Long taskId) {}
