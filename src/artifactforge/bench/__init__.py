# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The gradeable benchmark: scenes plus questions whose answers the artifacts encode.

Depends on: model, content, artifacts, compose. Nothing here may import ingest.
"""
from artifactforge.bench.benchmark import Question, Score, Task, generate_batch, grade

__all__ = ["Task", "Question", "Score", "generate_batch", "grade"]
