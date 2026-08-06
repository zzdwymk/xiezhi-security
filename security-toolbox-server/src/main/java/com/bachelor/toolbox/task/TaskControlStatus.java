package com.bachelor.toolbox.task;

/**
 * Runtime task-control policy and a snapshot of the current scheduler load. Keeping this separate
 * from a task row lets the desktop explain why a task is waiting without exposing executor
 * internals or mutable configuration.
 */
public record TaskControlStatus(
    int maxConcurrentTasks,
    int availableConcurrentSlots,
    int maxConcurrentTasksPerTarget,
    int queueCapacity,
    long pendingTasks,
    long runningTasks) {}
