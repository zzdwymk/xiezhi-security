package com.bachelor.toolbox.postscan;

import java.util.List;

record PostScanPlanDocument(
    String analysis,
    List<PostScanPathResponse.PathHypothesis> paths,
    List<PostScanPathResponse.RecommendedStep> steps) {}
