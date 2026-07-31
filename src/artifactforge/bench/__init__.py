# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The gradeable benchmark: scenes plus questions whose answers only the artifacts hold.

`Task` is server-side and carries the answers; `PublicTask` is everything a solver is given.
They are separate types so that handing a solver the wrong object is a type error rather than
a silent leak.

Depends on: model, suite, content, artifacts, compose. Nothing here may import ingest.
"""
from artifactforge.bench.benchmark import (
    PublicQuestion,
    PublicTask,
    Question,
    Score,
    Task,
    generate_batch,
    generate_suite,
    grade,
)

__all__ = ["Task", "PublicTask", "Question", "PublicQuestion", "Score",
           "generate_suite", "generate_batch", "grade"]
