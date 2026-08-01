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
from pathlib import Path

from artifactforge.inventory import (
    InventoryError,
    InventoryFile,
    captured_regular_tree,
    list_regular_file_paths,
)


SUPPORTED_FAMILIES = frozenset(("windows", "macos"))


def _require_supported_family(public) -> str:
    family = getattr(public, "family", None)
    if family not in SUPPORTED_FAMILIES:
        raise ValueError(f"unsupported benchmark family: {family!r}")
    return family


def _by_basename(files: tuple[InventoryFile, ...]) -> dict[str, InventoryFile]:
    """Index unambiguous basenames while preserving the historical flat-scene view."""
    indexed: dict[str, InventoryFile] = {}
    ambiguous: set[str] = set()
    for file in files:
        name = file.name
        if name in indexed or name in ambiguous:
            indexed.pop(name, None)
            ambiguous.add(name)
        else:
            indexed[name] = file
    return indexed


def _sqlite_fetchone(path: Path, sql: str, parameters: tuple = ()):
    """Run one read-only query and close the private-snapshot parser on every path."""
    import sqlite3

    uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        return connection.execute(sql, parameters).fetchone()
    finally:
        connection.close()


def blind_solve(public) -> dict:
    """Reconstruct answers from the public task alone, opening no artifact.

    Written against the shipped generator rather than a copy, so it cannot drift out of date:
    if generation stops being derivable from the public view, this solver stops scoring. It
    tries the published dev key first, because a dev suite is meant to be cheatable and the
    gate must see that it is.
    """
    from artifactforge import suite

    family = _require_supported_family(public)

    # Recover the batch index by searching the public id space under the published key. On a
    # dev suite this succeeds; on a hold-out suite the key is unknown and it cannot.
    key = suite.PUBLIC_DEV_KEY
    index = next((i for i in range(4096) if suite.public_id(key, i) == public.scenario_id),
                 None)
    if index is None:
        return {}
    skey = suite.scenario_key(key, public.scenario_id)

    a: dict = {}
    if family == "windows":
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
    elif family == "macos":
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
    _require_supported_family(public)
    a: dict = {}
    try:
        names = sorted(path.rsplit("/", 1)[-1]
                       for path in list_regular_file_paths(public.directory))
    except InventoryError:
        return a
    for f in names:
        if f.lower().endswith(".exe"):
            a.setdefault("orphan_execution", f)
        if f.endswith(".plist"):
            a.setdefault("granted_and_used_bundle", f[: -len(".plist")])
    return a


def null_solve(public) -> dict:
    """Answers nothing — the vacuous-pass guard."""
    _require_supported_family(public)
    return {}


def constant_solve(public) -> dict:
    """A fixed guess for every question, whatever it asks."""
    _require_supported_family(public)
    return {q.id: ("0" * 64 if q.kind in ("hash", "imphash") else "unknown")
            for q in public.questions}




def mechanical_solve(public) -> dict:
    """Exploit position: the answer is first in every stored sequence.

    It uses ordinary parsers to read stored order but performs no semantically meaningful join.
    It relies only on the generator having emitted the interesting record before the decoys —
    in the Run key, in the Amcache subkey list, and in every SQLite table. That is the family
    the owner's own wiki names: "an events file written in the order the agent was asked to
    reconstruct".
    """
    import hashlib
    family = _require_supported_family(public)
    d = public.directory
    a: dict = {}
    try:
        with captured_regular_tree(d) as files_context:
            files = _by_basename(files_context)
            blobs = {
                name: file.data
                for name, file in files.items()
                if file.data is not None
            }

            if family == "windows":
                run_file = files.get("Software.run.hive")
                if run_file is None:
                    return a
                try:
                    from regipy.registry import RegistryHive
                except ImportError:
                    return a
                run = RegistryHive(os.fspath(run_file.path)).get_key(
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
            elif family == "macos":
                tcc = files.get("TCC.db")
                if tcc is None:
                    return a
                try:
                    row = _sqlite_fetchone(tcc.path, "SELECT client FROM access")
                except Exception:                                  # noqa: BLE001 — best effort
                    return a
                if row:
                    a["granted_and_used_bundle"] = row[0]
            return a
    except InventoryError:
        return a


def footprint_solve(public) -> dict:
    """Exploit the scene's shape: the answer is whatever the other artifacts talk about most.

    The ranking step parses no format: for each candidate, count how many other files in the
    directory contain its name as a substring, and take the maximum. After choosing that pivot,
    the solver uses ordinary parsers and lookups to complete dependent answers. This is the
    strongest attack found, and it is structural rather than incidental: the target is by
    definition the object the registry, Amcache, prefetch and disk all mention, while a decoy
    appears in fewer of them. Counting mentions performs the intended selection without
    understanding any format.
    """
    import hashlib
    family = _require_supported_family(public)
    d = public.directory
    a: dict = {}
    try:
        with captured_regular_tree(d) as files_context:
            files = _by_basename(files_context)
            blobs = {
                name: file.data
                for name, file in files.items()
                if file.data is not None
            }

            def mentions(cand: str) -> int:
                pats = [cand.encode(), cand.upper().encode(), cand.lower().encode(),
                        cand.encode("utf-16-le"), cand.upper().encode("utf-16-le")]
                return sum(1 for f, b in blobs.items()
                           if f != cand and any(p in b for p in pats))

            if family == "windows":
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
            elif family == "macos":
                bundles = [f[: -len(".quarantine.xattr")] for f in blobs
                           if f.endswith(".quarantine.xattr")]
                if not bundles:
                    return a
                subject = max(bundles, key=mentions)
                a["granted_and_used_bundle"] = subject
                # Everything else about the subject is now a lookup in the subject's own files.
                try:
                    import plistlib
                    xattr = blobs[f"{subject}.quarantine.xattr"]
                    uuid = xattr.decode().strip().split(";")[-1]
                    quarantine = files["QuarantineEventsV2"]
                    row = _sqlite_fetchone(
                        quarantine.path,
                        "SELECT LSQuarantineDataURLString, LSQuarantineAgentName FROM "
                        "LSQuarantineEvent WHERE LSQuarantineEventIdentifier = ?",
                        (uuid,),
                    )
                    if row:
                        a["subject_download_url"], a["subject_quarantine_agent"] = row
                    launch_agent = blobs[f"{subject}.plist"]
                    a["subject_persistence_path"] = plistlib.loads(
                        launch_agent
                    )["ProgramArguments"][0]
                    data = blobs.get(subject)
                    if data:
                        a["subject_binary_sha256"] = hashlib.sha256(data).hexdigest()
                except Exception:                                  # noqa: BLE001 — best effort
                    pass
            return a
    except InventoryError:
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
