# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Adversary solvers — the benchmark's negative controls.

A benchmark is only measuring investigation if an agent that does no investigation scores
badly. The reference solver proves the answers are *recoverable* from the artifacts; these
prove they are not recoverable any *other* way. Both directions are needed, and only the
first was ever checked here.

Each solver below is an attack, and each must stay in the suite permanently. The moment one
of them scores well, the benchmark has stopped measuring what it claims to.

  blind_solve    reads only the public task view; opens ZERO files. Because the generator is
                 open source, anything derivable from a public identifier is free. This is
                 the strongest attack and the reason the public identifier must not be the
                 generation seed.
  listing_solve  reads only the artifact FILENAMES. Answers that appear in a filename —
                 an executable's name, a bundle id in `<id>.plist` — cost nothing.
  null_solve     answers nothing. The floor.
  constant_solve answers a fixed string. A floor so weak it flatters the scorer; kept only
                 because removing it would lose the historical baseline.
"""
from __future__ import annotations

import os


def blind_solve(public: dict, directory: str | None = None) -> dict:
    """Reconstruct answers from the public identifier alone, opening no artifact.

    Mirrors `generate_batch`'s derivation exactly. It is deliberately written against the
    shipped generator rather than against a copy, so it cannot silently drift out of date:
    if generation stops being derivable from the public view, this solver stops scoring.
    """
    from artifactforge.bench.benchmark import _BUNDLES, _HOSTS, _MALNAMES, _USERS, _pick
    from artifactforge.content import ContentStore
    from artifactforge.model import deterministic_uuid, macos_profile, windows_profile

    sid = public["scenario_id"]
    if not sid.startswith("scenario_"):
        return {}                       # opaque identifier — nothing to derive from
    try:
        i = int(sid.split("_", 1)[1])
    except ValueError:
        return {}

    a: dict = {}
    if public["family"] == "windows":
        name = _pick(i, _MALNAMES)
        prof = windows_profile(hostname=f"{_pick(i, _HOSTS)}-{i:03d}", username=_pick(i, _USERS))
        cache = os.path.join(directory or ".", ".blind-cache")
        c = ContentStore(f"artifactforge::{sid}", cache).materialize(f"pe:{sid}:{name}")
        a["dropped_sha256"] = c.sha256
        a["imphash"] = c.imphash
        a["amcache_sha1"] = c.sha1
        a["persistence_path"] = f"{prof.home_dir}\\AppData\\Local\\Temp\\{name}"
        a["exec_name"] = name
        a["run_count"] = 1 + (i % 9)
    else:
        prof = macos_profile(hostname=f"mac-{i:03d}", username=_pick(i, _USERS))
        bundle = _pick(i, _BUNDLES)
        a["quarantine_uuid"] = deterministic_uuid(prof.seed_tag() + ":" + bundle)
        a["download_url"] = f"https://cdn{i}.evil.example/{bundle}.dmg"
        a["tcc_bundle_id"] = bundle
        a["persistence_path"] = f"{prof.home_dir}/Library/Application Support/{bundle}/agent"
    return a


def listing_solve(public: dict, directory: str | None = None) -> dict:
    """Answer from artifact filenames only — never opening a single file."""
    a: dict = {}
    for f in public.get("artifacts", []):
        if f.lower().endswith(".exe"):
            a["exec_name"] = f
        if f.endswith(".plist"):
            a["tcc_bundle_id"] = f[: -len(".plist")]
    return a


def null_solve(public: dict, directory: str | None = None) -> dict:
    """Answers nothing — the vacuous-pass guard."""
    return {}


def constant_solve(public: dict, directory: str | None = None) -> dict:
    """A fixed guess for every question, whatever it asks."""
    return {q["id"]: ("0" * 64 if q["kind"] in ("hash", "imphash") else "unknown")
            for q in public.get("questions", [])}


#: name -> (solver, the score above which the benchmark is considered gameable)
ADVERSARIES = {
    "blind": (blind_solve, 0.10),
    "listing": (listing_solve, 0.10),
    "null": (null_solve, 0.0),
    "constant": (constant_solve, 0.05),
}
