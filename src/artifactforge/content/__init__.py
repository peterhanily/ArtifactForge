# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Materialized file content and its identity.

`ContentStore` synthesizes a binary's bytes once from a seed and derives that ``Content``
object's content and structural hashes from the bytes it emits. A caller that populates several
declared fields from the same object gets a consistent identity by construction. Scene-level
stale and absent decoy hashes are outside this module's guarantee.

Depends on: model. Nothing here may import artifacts, compose, bench or ingest.
"""
from artifactforge.content.macho import build_macho, cdhash_of_file, symhash_of
from artifactforge.content.seed import prng_bytes, sub_seed
from artifactforge.content.store import Content, ContentStore, build_pe_stub, imphash_of

__all__ = ["Content", "ContentStore", "build_pe_stub", "imphash_of",
           "build_macho", "symhash_of", "cdhash_of_file", "sub_seed", "prng_bytes"]
