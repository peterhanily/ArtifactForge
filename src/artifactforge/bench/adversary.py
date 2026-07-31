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
        from artifactforge.content import ContentStore
        from artifactforge.model import macos_profile
        subject = suite.pick_many(skey, "bundles", pools.BUNDLES, 3)[0]
        host = suite.pick(skey, f"dlhost:{subject}", pools.DOWNLOAD_HOSTS)
        cache = os.path.join(public.directory, "..", "..", "_blind-cache")
        store = ContentStore("artifactforge::suite", os.path.abspath(cache))
        c = store.materialize(f"macho:{subject}:" + suite.content_seed(skey, f"macho:{subject}"))
        profile = macos_profile(username=suite.pick(skey, "user", pools.USERS))
        a["granted_and_used_bundle"] = subject
        a["subject_download_url"] = f"https://{host}/{subject}.dmg"
        a["subject_quarantine_agent"] = suite.pick(skey, f"agent:{subject}",
                                                   pools.DOWNLOAD_AGENTS)
        a["subject_binary_sha256"] = c.sha256
        a["subject_binary_symhash"] = c.symhash
        a["subject_persistence_path"] = (f"{profile.home_dir}/Library/Application Support/"
                                         f"{subject}/{subject.rsplit('.', 1)[-1]}")
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




def mechanical_solve(public) -> dict:
    """Exploit position: the answer is first in every stored sequence.

    Reads the artifacts, parses nothing meaningfully, joins nothing. It relies only on the
    generator having emitted the interesting record before the decoys — in the Run key, in the
    Amcache subkey list, and in every SQLite table. That is the family the owner's own wiki
    names: "an events file written in the order the agent was asked to reconstruct".
    """
    import hashlib
    d = public.directory
    a: dict = {}
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return a
    blobs = {}
    for n in names:
        p = os.path.join(d, n)
        if os.path.isfile(p):
            with open(p, "rb") as f:
                blobs[n] = f.read()

    if public.family == "windows":
        try:
            from regipy.registry import RegistryHive
        except ImportError:
            return a
        run = RegistryHive(os.path.join(d, "Software.run.hive")).get_key(
            "\\Microsoft\\Windows\\CurrentVersion\\Run")
        values = [v.value for v in run.get_values()]
        if not values:
            return a
        target = values[0].replace("/", "\\").rsplit("\\", 1)[-1]
        for name, data in blobs.items():
            if name.lower() == target.lower():
                a["persisted_sha256"] = hashlib.sha256(data).hexdigest()
                try:
                    import pefile
                    a["persisted_imphash"] = pefile.PE(data=data).get_imphash()
                except Exception:                          # noqa: BLE001 — best effort
                    pass
    else:
        try:
            import sqlite3
            con = sqlite3.connect(os.path.join(d, "TCC.db"))
            row = con.execute("SELECT client FROM access").fetchone()
            con.close()
        except Exception:                                  # noqa: BLE001 — best effort
            return a
        if row:
            a["granted_and_used_bundle"] = row[0]
    return a


def footprint_solve(public) -> dict:
    """Exploit the scene's shape: the answer is whatever the other artifacts talk about most.

    No parsing at all — for each candidate, count how many other files in the directory
    contain its name as a substring, and take the maximum. This is the strongest attack found,
    and it is structural rather than incidental: the target is by definition the object the
    registry, Amcache, prefetch and disk all mention, while a decoy appears in fewer of them.
    Counting mentions IS the intended pivot, performed without understanding any of it.
    """
    import hashlib
    d = public.directory
    a: dict = {}
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return a
    blobs = {}
    for n in names:
        p = os.path.join(d, n)
        if os.path.isfile(p):
            with open(p, "rb") as f:
                blobs[n] = f.read()

    def mentions(cand: str) -> int:
        pats = [cand.encode(), cand.upper().encode(), cand.lower().encode(),
                cand.encode("utf-16-le"), cand.upper().encode("utf-16-le")]
        return sum(1 for f, b in blobs.items() if f != cand and any(p in b for p in pats))

    if public.family == "windows":
        pes = [f for f, b in blobs.items() if b[:2] == b"MZ"]
        if not pes:
            return a
        ranked = sorted(pes, key=mentions, reverse=True)
        a["persisted_sha256"] = hashlib.sha256(blobs[ranked[0]]).hexdigest()
        try:
            import pefile
            a["persisted_imphash"] = pefile.PE(data=blobs[ranked[0]]).get_imphash()
        except Exception:                                  # noqa: BLE001 — best effort
            pass
        if len(ranked) > 1:
            a["amcache_match_sha256"] = hashlib.sha256(blobs[ranked[1]]).hexdigest()
    else:
        bundles = [f[: -len(".quarantine.xattr")] for f in blobs
                   if f.endswith(".quarantine.xattr")]
        if not bundles:
            return a
        subject = max(bundles, key=mentions)
        a["granted_and_used_bundle"] = subject
        # Everything else about the subject is now a lookup in the subject's own files.
        try:
            import plistlib
            import sqlite3
            with open(os.path.join(d, f"{subject}.quarantine.xattr")) as f:
                uuid = f.read().strip().split(";")[-1]
            con = sqlite3.connect(os.path.join(d, "QuarantineEventsV2"))
            row = con.execute(
                "SELECT LSQuarantineDataURLString, LSQuarantineAgentName FROM "
                "LSQuarantineEvent WHERE LSQuarantineEventIdentifier = ?", (uuid,)).fetchone()
            con.close()
            if row:
                a["subject_download_url"], a["subject_quarantine_agent"] = row
            with open(os.path.join(d, f"{subject}.plist"), "rb") as f:
                a["subject_persistence_path"] = plistlib.load(f)["ProgramArguments"][0]
            data = blobs.get(subject)
            if data:
                a["subject_binary_sha256"] = hashlib.sha256(data).hexdigest()
        except Exception:                                  # noqa: BLE001 — best effort
            pass
    return a


#: name -> (solver, the score above which the benchmark is considered gameable).
#:
#: The first two are the ones that matter. `null` and `constant` score 0.0000, which is BELOW
#: the chance floor of a solver that simply guesses among the visible candidates — keeping them
#: as the only baselines flattered every number this benchmark ever published.
ADVERSARIES = {
    "footprint": (footprint_solve, 0.30),
    "mechanical": (mechanical_solve, 0.30),
    "blind": (blind_solve, 0.10),
    "listing": (listing_solve, 0.10),
    "null": (null_solve, 0.0),
    "constant": (constant_solve, 0.05),
}
