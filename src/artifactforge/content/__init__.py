# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""File content and its identity — the layer every hash-shaped field is derived from.

`ContentStore` synthesizes a file's real bytes once from a seed; every artifact that
mentions that file quotes a genuine digest of those same bytes, so the cross-artifact
hash pivot holds by construction rather than by assertion.

Depends on: model. Nothing here may import artifacts, compose, bench or ingest.
"""
from artifactforge.content.macho import build_macho, cdhash_of_file, symhash_of
from artifactforge.content.seed import prng_bytes, sub_seed
from artifactforge.content.store import Content, ContentStore, build_pe_stub, imphash_of

__all__ = ["Content", "ContentStore", "build_pe_stub", "imphash_of",
           "build_macho", "symhash_of", "cdhash_of_file", "sub_seed", "prng_bytes"]
