# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Adversary solvers — the benchmark's negative controls.

A benchmark only measures investigation if an agent that does no investigation scores badly.
The reference solver proves the answers are *recoverable* from the artifacts; these prove
they are not recoverable any *other* way. Both directions are needed, and only the first was
ever checked here — while a solver opening zero files was scoring 100%.

Each of these is an attack, and each stays in the suite permanently. The moment one scores
well, the benchmark has stopped measuring what it claims to.

  blind     knows the entire generator source and the published dev key, and reads only the
            public task. Opens no artifact. This is the strongest attack: anything derivable
            from a public identifier is free, which is why the identifier is an HMAC of a
            suite key rather than the seed itself.
  listing   reads only the filenames in the served directory. Answers that appear in a name
            cost nothing, which is why no question's answer is a resident filename.
  null      answers nothing. The floor.
  constant  a fixed guess for everything. A floor weak enough to flatter the scorer, kept
            only so the historical baseline stays comparable.
"""
from __future__ import annotations

import os


def blind_solve(public) -> dict:
    """Reconstruct answers from the public task alone, opening no artifact.

    Written against the shipped generator rather than a copy, so it cannot drift out of date:
    if generation stops being derivable from the public view, this solver stops scoring. It
    tries the published dev key first, because a dev suite is meant to be cheatable and the
    gate must see that it is.
    """
    from artifactforge import suite

    # Recover the batch index by searching the public id space under the published key. On a
    # dev suite this succeeds; on a hold-out suite the key is unknown and it cannot.
    key = suite.PUBLIC_DEV_KEY
    index = next((i for i in range(4096) if suite.public_id(key, i) == public.scenario_id),
                 None)
    if index is None:
        return {}
    skey = suite.scenario_key(key, public.scenario_id)

    a: dict = {}
    if public.family == "windows":
        from artifactforge import pools
        from artifactforge.content import ContentStore
        cache = os.path.join(public.directory, "..", "..", "_blind-cache")
        store = ContentStore("artifactforge::suite", os.path.abspath(cache))
        persisted = store.materialize("pe:" + suite.content_seed(skey, "persisted"))
        matched = store.materialize("pe:" + suite.content_seed(skey, "amcache-match"))
        a["persisted_sha256"] = persisted.sha256
        a["persisted_imphash"] = persisted.imphash
        a["persisted_run_count"] = 1 + skey[0] % 9
        a["amcache_match_sha256"] = matched.sha256
        a["orphan_execution"] = suite.pick(
            skey, "absent",
            [n for n in pools.MALWARE_NAMES
             if n != suite.pick(skey, "persisted-name", pools.MALWARE_NAMES)])
    else:
        from artifactforge import pools
        subject = suite.pick_many(skey, "bundles", pools.BUNDLES, 3)[0]
        host = suite.pick(skey, f"dlhost:{subject}", pools.DOWNLOAD_HOSTS)
        a["granted_and_used_bundle"] = subject
        a["subject_download_url"] = f"https://{host}/{subject}.dmg"
        a["subject_quarantine_agent"] = suite.pick(skey, f"agent:{subject}",
                                                   pools.DOWNLOAD_AGENTS)
    return a


def listing_solve(public) -> dict:
    """Answer from the served directory's filenames only — never opening a file."""
    a: dict = {}
    try:
        names = sorted(os.listdir(public.directory))
    except OSError:
        return a
    for f in names:
        if f.lower().endswith(".exe"):
            a.setdefault("orphan_execution", f)
        if f.endswith(".plist"):
            a.setdefault("granted_and_used_bundle", f[: -len(".plist")])
    return a


def null_solve(public) -> dict:
    """Answers nothing — the vacuous-pass guard."""
    return {}


def constant_solve(public) -> dict:
    """A fixed guess for every question, whatever it asks."""
    return {q.id: ("0" * 64 if q.kind in ("hash", "imphash") else "unknown")
            for q in public.questions}


#: name -> (solver, the score above which the benchmark is considered gameable)
ADVERSARIES = {
    "blind": (blind_solve, 0.10),
    "listing": (listing_solve, 0.10),
    "null": (null_solve, 0.0),
    "constant": (constant_solve, 0.05),
}
