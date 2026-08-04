# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 2 — identity: do the declared answer-bearing pivots agree with emitted bytes?

This is the keystone. EvidenceForge's Sysmon and Zeek paths use emitter-local synthetic seed
domains rather than shared file bytes. Their same-algorithm sets are disjoint in the measured
stock run, but that run contains no basename-matched transfer/execution pair and therefore is
not proof that one logical binary received two inconsistent hashes. ArtifactForge's scoped
answer is to synthesize each answer-bearing binary once and reuse its ``Content`` identity in
the declared joins.

The gate is written to be falsifiable in the one way that matters: each value in its declared
scope is re-derived from the FILES ON DISK, through a real parser where appropriate, and only
then compared. Deliberate stale and absent Amcache decoy hashes are not claims about resident
bytes and are outside this gate. The predecessor of this gate asserted
`amcache == "0000" + c.sha1` one line after assigning `amcache = "0000" + c.sha1`, and stayed
green when the underlying hash was replaced with a placeholder string.

The join is passed in rather than read from the scene, because the answer key does not live
in a directory a solver can see. Every check names the two artifacts it spans: a check
confined to one artifact cannot detect a broken pivot.
"""
from __future__ import annotations

import hashlib
import os
import plistlib
import re
import sqlite3
import struct

from artifactforge.gates import GateReport
from artifactforge.inventory import InventoryError, InventoryFile, captured_regular_tree


_LINUX_HISTORY_MARKER = ": 'ARTIFACTFORGE-SYNTHETIC-LINUX'"
_CHROMIUM_CONTENT_URL = re.compile(
    r"https://downloads\.artifactforge\.invalid/ARTIFACTFORGE/sha256/"
    r"(?P<sha256>[0-9a-f]{64})/(?P<name>[^/?#]+)"
)


def _check(r: GateReport, spans: str, what: str, got, want):
    """One cross-artifact equality, counted whether it holds or not."""
    r.metrics["checks_total"] = r.metrics.get("checks_total", 0) + 1
    if got == want:
        r.metrics["checks_joined"] = r.metrics.get("checks_joined", 0) + 1
        return True
    r.fail(f"{spans}: {what} — evidence says {str(got)[:64]!r}, "
           f"the scene claims {str(want)[:64]!r}")
    return False


def _named(
    r: GateReport, files: tuple[InventoryFile, ...], name: str, where: str
) -> InventoryFile | None:
    matches = [file for file in files if file.name == name]
    if not matches:
        r.fail(f"{where}: required artifact {name!r} is absent from the scene")
        return None
    if len(matches) != 1:
        r.fail(
            f"{where}: required artifact basename {name!r} is ambiguous across "
            + ", ".join(file.relative_path for file in matches)
        )
        return None
    return matches[0]


def _relative(
    r: GateReport, files: tuple[InventoryFile, ...], relative_path: str, where: str
) -> InventoryFile | None:
    """Resolve an exact recursive served path without falling back to a basename."""
    matches = [file for file in files if file.relative_path == relative_path]
    if len(matches) != 1:
        observed = "absent" if not matches else f"present {len(matches)} times"
        r.fail(f"{where}: exact served artifact {relative_path!r} is {observed}")
        return None
    return matches[0]


def _resident(r: GateReport, scene_files: tuple[InventoryFile, ...]) -> dict:
    out = {}
    ambiguous = set()
    for file in scene_files:
        data = file.data
        if data is None:
            raise AssertionError("identity inventory did not capture file bytes")
        if data[:2] == b"MZ":
            key = file.name.lower()
            if key in out or key in ambiguous:
                out.pop(key, None)
                ambiguous.add(key)
                locations = [candidate.relative_path for candidate in scene_files
                             if candidate.name.lower() == key]
                r.fail(
                    f"disk: resident binary basename {file.name!r} is ambiguous across "
                    + ", ".join(locations)
                )
                continue
            out[key] = data
    return out


def _q(file: InventoryFile, sql: str):
    con = sqlite3.connect(file.path.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def _windows(
    r: GateReport, scene_files: tuple[InventoryFile, ...], join: dict
):
    import pefile
    from regipy.registry import RegistryHive

    from artifactforge.artifacts.shell_link import parse_shell_link
    from artifactforge.artifacts.windows_task import (
        parse_scheduled_task_xml,
        read_scheduled_task_xml_wire,
        validate_scheduled_task_xml,
    )
    from artifactforge.gates.oracles.prefetch_profile import (
        parse_mam_prefetch_v30_variant1,
    )

    files = _resident(r, scene_files)
    p = join["persisted"]
    resident_claims = join.get("residents", [])
    _check(r, "resident truth->disk", "five declared resident PEs",
           len(resident_claims), 5)
    _check(r, "resident truth->disk", "exact resident PE names",
           sorted(claim.get("name", "").lower() for claim in resident_claims),
           sorted(files))
    _check(r, "resident bytes", "one fixed PE file size",
           len({len(data) for data in files.values()}), 1)

    for claim in resident_claims:
        label = claim.get("role", "resident")
        data = files.get(claim["name"].lower())
        if data is None:
            r.fail(f"disk: the {label} binary {claim['name']!r} is not in the scene, so its "
                   f"hashes are claims about a file nobody can check")
            continue
        _check(r, f"disk->{label}", "size", len(data), claim["size"])
        _check(r, f"disk->{label}", "sha256", hashlib.sha256(data).hexdigest(), claim["sha256"])
        _check(r, f"disk->{label}", "sha1",
               hashlib.sha1(data).hexdigest(), claim["sha1"])         # noqa: S324 - identity
        _check(r, f"disk->{label}", "md5",
               hashlib.md5(data).hexdigest(), claim["md5"])           # noqa: S324 - identity
        _check(r, f"pefile->{label}", "imphash",
               pefile.PE(data=data).get_imphash(), claim["imphash"])

    # The five public-grade registry->disk pivots form a bijection. Historical path and Name
    # values deliberately do not name the current file; only FileId SHA1 agrees with bytes.
    by_sha1 = {hashlib.sha1(d).hexdigest(): n                         # noqa: S324 - identity
               for n, d in files.items()}
    amcache_file = _named(r, scene_files, "Amcache.hve", "Amcache")
    if amcache_file is not None:
        iaf = RegistryHive(os.fspath(amcache_file.path)).get_key(
            "\\Root\\InventoryApplicationFile")
        rows = []
        for subkey in iaf.iter_subkeys():
            values = {value.name: value.value for value in subkey.get_values()}
            rows.append(values)
        rows_by_path = {row.get("LowerCaseLongPath"): row for row in rows}
        matches = sorted(
            by_sha1[row["FileId"][4:]]
            for row in rows
            if isinstance(row.get("FileId"), str) and row["FileId"][4:] in by_sha1
        )
        _check(r, "Amcache->disk", "five recorded hashes cover every resident PE",
               matches, sorted(files))

        relations = join.get("benchmark_relations", [])
        candidates = join.get("benchmark_candidates", [])
        _check(r, "benchmark truth->Amcache", "five declared relations", len(relations), 5)
        _check(r, "benchmark truth->disk", "five declared candidates", len(candidates), 5)
        _check(r, "benchmark candidates->disk", "candidate SHA256 set",
               sorted(candidate.get("value", "") for candidate in candidates),
               sorted(hashlib.sha256(data).hexdigest() for data in files.values()))

        related_names = []
        for index, relation in enumerate(relations):
            selector = relation.get("selector", {})
            historical_path = selector.get("lower_case_long_path")
            row = rows_by_path.get(historical_path)
            if row is None:
                r.fail(
                    f"Amcache relation {index}: selector {historical_path!r} matches no row"
                )
                continue
            link_value = relation.get("link_value")
            _check(r, "Amcache row->relation", "FileId SHA1",
                   row.get("FileId"), "0000" + str(link_value))
            current_name = relation.get("candidate", "").lower()
            related_names.append(current_name)
            data = files.get(current_name)
            if data is None:
                r.fail(f"Amcache relation {index}: candidate {current_name!r} is not resident")
                continue
            _check(r, "Amcache FileId->resident bytes", "SHA1 agreement",
                   hashlib.sha1(data).hexdigest(), link_value)          # noqa: S324
            _check(r, "resident bytes->question answer", "SHA256",
                   hashlib.sha256(data).hexdigest(), relation.get("expected"))
            historical_name = str(row.get("Name", "")).lower()
            _check(r, "Amcache historical row->disk", "name is not a current resident",
                   historical_name in files, False)
        _check(r, "benchmark relations->disk", "one relation per resident PE",
               sorted(related_names), sorted(files))

    # The persistence->disk pivot: exactly one autostart names a program that is here.
    run_file = _named(r, scene_files, "Software.run.hive", "Run key")
    if run_file is not None:
        run = RegistryHive(os.fspath(run_file.path)).get_key(
            "\\Microsoft\\Windows\\CurrentVersion\\Run")
        named = sorted(v.value for v in run.get_values()
                       if v.value.replace("/", "\\").rsplit("\\", 1)[-1].lower() in files)
        _check(r, "Run key->disk", "exactly one autostart names a resident program",
               named, [p["path"]])

    # Chromium's completed-download hash BLOB is genuinely empty.  The byte relation is the
    # explicitly synthetic, content-addressed final URL: its digest is recomputed from the
    # only resident target, while two absent download rows remain ordinary noise.  Fixture v2
    # separately projects this row's source/referrer pair into that PE's Zone.Identifier.
    history = _named(r, scene_files, "History", "Chromium download history")
    browser_truth = join.get("browser_download", {})
    if history is not None:
        browser_rows = _q(
            history,
            "SELECT d.target_path,d.received_bytes,d.total_bytes,d.hash,d.state,"
            "d.opened,d.last_access_time,d.referrer,u.url FROM downloads AS d "
            "JOIN downloads_url_chains AS u ON u.id=d.id "
            "ORDER BY d.id,u.chain_index",
        )
        _check(r, "History", "three completed download rows", len(browser_rows), 3)
        resident_downloads = []
        rows_by_target = {}
        for row in browser_rows:
            target, received, total, stored_hash, state, _opened, _access, _referrer, url = row
            rows_by_target[target] = row
            match = _CHROMIUM_CONTENT_URL.fullmatch(url) if type(url) is str else None
            if match is None:
                r.fail(f"History: source URL for {target!r} has no content-addressed identity")
                continue
            target_name = str(target).rsplit("\\", 1)[-1].lower()
            if match.group("name").lower() != target_name:
                r.fail(f"History: source URL basename disagrees with target {target!r}")
                continue
            data = files.get(target_name)
            if data is None:
                continue
            _check(
                r,
                "History URL->resident bytes",
                "SHA256 agreement",
                match.group("sha256"),
                hashlib.sha256(data).hexdigest(),
            )
            _check(
                r,
                "History size->resident bytes",
                "received/total size agreement",
                (received, total),
                (len(data), len(data)),
            )
            _check(r, "History completed row", "native-empty hash BLOB", stored_hash, b"")
            _check(r, "History completed row", "complete state", state, 1)
            resident_downloads.append(target)
        _check(
            r,
            "History->disk",
            "exactly one completed download names resident bytes",
            sorted(resident_downloads),
            [browser_truth.get("target_path")],
        )
        truth_row = rows_by_target.get(browser_truth.get("target_path"))
        if truth_row is None:
            r.fail("History: declared browser-download target matches no row")
        else:
            target, received, total, _stored_hash, _state, _opened, _access, referrer, url = (
                truth_row
            )
            _check(r, "History->scene relation", "target path", target, p["path"])
            _check(
                r,
                "History->scene relation",
                "content-addressed source URL",
                url,
                browser_truth.get("source_url"),
            )
            _check(
                r,
                "History->scene relation",
                "referrer URL",
                referrer,
                browser_truth.get("referrer_url"),
            )
            _check(
                r,
                "History->scene relation",
                "recorded size",
                (received, total),
                (browser_truth.get("size"), browser_truth.get("size")),
            )
            match = _CHROMIUM_CONTENT_URL.fullmatch(url)
            _check(
                r,
                "History URL->scene relation",
                "declared SHA256",
                match.group("sha256") if match else None,
                browser_truth.get("sha256"),
            )

    # These are reference/configuration joins, not execution claims.  Each strict first-party
    # reader resolves a path from the emitted bytes; only then do we map that exact path to one
    # declared resident and re-hash the target bytes.  The Task is disabled and trigger-free,
    # while the Shell Link has no arguments or activation data under its closed profile.
    claims_by_path: dict[str, list[dict]] = {}
    for claim in resident_claims:
        if not isinstance(claim, dict) or not isinstance(claim.get("path"), str):
            continue
        claims_by_path.setdefault(claim["path"].casefold(), []).append(claim)

    scheduled_truth = join.get("scheduled_task", {})
    scheduled_source = scheduled_truth.get("source")
    task_inventory = sorted(
        file.relative_path
        for file in scene_files
        if file.name.casefold().endswith(".task.xml")
    )
    _check(
        r,
        "scene inventory->scheduled task",
        "exactly one declared Task XML",
        task_inventory,
        [scheduled_source] if isinstance(scheduled_source, str) else [],
    )
    task_file = (
        _relative(r, scene_files, scheduled_source, "scheduled task")
        if isinstance(scheduled_source, str)
        else None
    )
    task_target_path = None
    if task_file is not None and task_file.data is not None:
        try:
            task_value = parse_scheduled_task_xml(task_file.data)
            task_wire = read_scheduled_task_xml_wire(task_file.data)
        except ValueError as exc:
            r.fail(f"scheduled task: strict first-party readers rejected it — {exc}")
        else:
            task_target_path = task_value.command
            _check(
                r,
                "Task XML parser->wire reader",
                "command",
                task_value.command,
                task_wire.command,
            )
            _check(
                r,
                "Task XML->scene relation",
                "disabled trigger-free one-action profile",
                (
                    task_value.enabled,
                    task_value.allow_start_on_demand,
                    task_value.trigger_count,
                    task_value.action_count,
                ),
                (False, False, 0, 1),
            )
            _check(
                r,
                "Task XML->scene relation",
                "task name",
                task_value.task_name,
                scheduled_truth.get("task_name"),
            )
            _check(
                r,
                "Task XML->scene relation",
                "native Task-store guest path",
                scheduled_truth.get("guest_path"),
                rf"C:\Windows\System32\Tasks\ArtifactForge\{task_value.task_name}",
            )
            _check(
                r,
                "Task XML->scene relation",
                "target path",
                task_value.command,
                scheduled_truth.get("target_path"),
            )
            target_claims = claims_by_path.get(task_value.command.casefold(), [])
            _check(
                r,
                "Task XML->resident truth",
                "exactly one resident target",
                len(target_claims),
                1,
            )
            if len(target_claims) == 1:
                claim = target_claims[0]
                try:
                    validate_scheduled_task_xml(
                        task_file.data,
                        resident_pe_paths=(claim["path"],),
                    )
                except ValueError as exc:
                    r.fail(f"scheduled task: selected resident validation failed — {exc}")
                target_data = files.get(str(claim.get("name", "")).lower())
                if target_data is None:
                    r.fail("scheduled task: resolved target has no unique resident PE bytes")
                else:
                    _check(
                        r,
                        "Task XML->resident bytes",
                        "target filename",
                        claim.get("name"),
                        scheduled_truth.get("target_name"),
                    )
                    _check(
                        r,
                        "Task XML->resident truth",
                        "target role",
                        claim.get("role"),
                        scheduled_truth.get("target_role"),
                    )
                    _check(
                        r,
                        "Task XML->resident bytes",
                        "target size",
                        len(target_data),
                        scheduled_truth.get("target_size"),
                    )
                    _check(
                        r,
                        "Task XML->resident bytes",
                        "target SHA256",
                        hashlib.sha256(target_data).hexdigest(),
                        scheduled_truth.get("target_sha256"),
                    )

    shell_truth = join.get("shell_link", {})
    shell_source = shell_truth.get("source")
    shell_inventory = sorted(
        file.relative_path
        for file in scene_files
        if file.name.casefold().endswith(".lnk")
    )
    _check(
        r,
        "scene inventory->Shell Link",
        "exactly one declared Shell Link",
        shell_inventory,
        [shell_source] if isinstance(shell_source, str) else [],
    )
    shell_file = (
        _relative(r, scene_files, shell_source, "Shell Link")
        if isinstance(shell_source, str)
        else None
    )
    shell_target_path = None
    if shell_file is not None and shell_file.data is not None:
        try:
            shell_value = parse_shell_link(shell_file.data)
        except ValueError as exc:
            r.fail(f"Shell Link: strict first-party reader rejected it — {exc}")
        else:
            shell_target_path = shell_value.target_path
            _check(
                r,
                "Shell Link->scene relation",
                "target path",
                shell_value.target_path,
                shell_truth.get("target_path"),
            )
            _check(
                r,
                "Shell Link->scene relation",
                "Start Menu guest path",
                shell_truth.get("guest_path"),
                (
                    f"C:\\Users\\{join.get('user')}\\AppData\\Roaming\\Microsoft\\"
                    f"Windows\\Start Menu\\Programs\\{shell_file.name}"
                ),
            )
            target_claims = claims_by_path.get(shell_value.target_path.casefold(), [])
            _check(
                r,
                "Shell Link->resident truth",
                "exactly one resident target",
                len(target_claims),
                1,
            )
            if len(target_claims) == 1:
                claim = target_claims[0]
                target_data = files.get(str(claim.get("name", "")).lower())
                if target_data is None:
                    r.fail("Shell Link: resolved target has no unique resident PE bytes")
                else:
                    _check(
                        r,
                        "Shell Link->resident bytes",
                        "target filename",
                        claim.get("name"),
                        shell_truth.get("target_name"),
                    )
                    _check(
                        r,
                        "Shell Link->resident truth",
                        "target role",
                        claim.get("role"),
                        shell_truth.get("target_role"),
                    )
                    _check(
                        r,
                        "Shell Link->resident bytes",
                        "header target size",
                        shell_value.target_size,
                        len(target_data),
                    )
                    _check(
                        r,
                        "Shell Link->resident bytes",
                        "declared target size",
                        len(target_data),
                        shell_truth.get("target_size"),
                    )
                    _check(
                        r,
                        "Shell Link->resident bytes",
                        "target SHA256",
                        hashlib.sha256(target_data).hexdigest(),
                        shell_truth.get("target_sha256"),
                    )
            _check(
                r,
                "Shell Link->scene relation",
                "target FILETIMEs",
                (
                    shell_value.creation_filetime,
                    shell_value.access_filetime,
                    shell_value.write_filetime,
                ),
                (
                    shell_truth.get("creation_filetime"),
                    shell_truth.get("access_filetime"),
                    shell_truth.get("write_filetime"),
                ),
            )
            _check(
                r,
                "Shell Link->scene relation",
                "fixed-volume serial",
                shell_value.volume_serial,
                shell_truth.get("volume_serial"),
            )
    if task_target_path is not None and shell_target_path is not None:
        _check(
            r,
            "Task XML<->Shell Link",
            "distinct non-persistence resident targets",
            task_target_path.casefold() != shell_target_path.casefold(),
            True,
        )
        _check(
            r,
            "Task XML/Shell Link->Run relation",
            "neither reference amplifies the persisted target",
            {
                task_target_path.casefold(),
                shell_target_path.casefold(),
            }.isdisjoint({str(p.get("path", "")).casefold()}),
            True,
        )

    # The execution pivot: the exact declared Prefetch set, the persisted program's run
    # count, and exactly one orphan.  Artifact count comes from the captured served tree and
    # execution names come from decoding those bytes; neither is inferred from filenames.
    prefetch_truth = join.get("prefetch")
    if not isinstance(prefetch_truth, dict):
        prefetch_truth = {}
        r.fail("prefetch truth: declaration must be a mapping")
    expected_prefetch_names = prefetch_truth.get("execution_names", [])
    if not isinstance(expected_prefetch_names, list) or not all(
        isinstance(name, str) for name in expected_prefetch_names
    ):
        expected_prefetch_names = []
        r.fail("prefetch truth: execution_names must be a list of strings")
    expected_prefetch_names = sorted(name.casefold() for name in expected_prefetch_names)
    prefetch_files = [file for file in scene_files if file.name.casefold().endswith(".pf")]
    _check(
        r,
        "prefetch truth->disk",
        "exact Prefetch artifact count",
        len(prefetch_files),
        prefetch_truth.get("artifact_count"),
    )
    prefetches = {}
    for file in prefetch_files:
        if file.data is None:
            r.fail(f"prefetch: {file.relative_path} has no captured bytes")
            continue
        try:
            pf = parse_mam_prefetch_v30_variant1(file.data)
        except (TypeError, ValueError) as exc:
            r.fail(
                f"prefetch: {file.relative_path} is outside the bounded v30 profile — "
                f"{type(exc).__name__}: {str(exc)[:100]}"
            )
            continue
        key = pf.executable_name.lower()
        if key in prefetches:
            r.fail(f"prefetch: executable name {pf.executable_name!r} is ambiguous")
            continue
        prefetches[key] = pf.run_count
    _check(
        r,
        "prefetch bytes->scene truth",
        "exact execution names",
        sorted(prefetches),
        expected_prefetch_names,
    )
    if p["name"].lower() in prefetches:
        _check(r, "prefetch->persisted", "run count",
               prefetches[p["name"].lower()], p["run_count"])
    else:
        r.fail("prefetch: the persisted program has no execution record to join to")
    _check(r, "prefetch->disk", "exactly one execution record names an absent program",
           sorted(n for n in prefetches if n not in files),
           [join["orphan_execution"].lower()])


def _macos(
    r: GateReport, scene_files: tuple[InventoryFile, ...], join: dict
):
    import lief

    from artifactforge.artifacts.macos import parse_quarantine_xattr
    from artifactforge.content.macho import cdhash_of_file

    s = join["subject"]

    # The macOS half of the keystone: all five candidate binaries are real Mach-O files and
    # every hash-shaped claim is re-derived from their emitted bytes.
    binary_claims = join.get("binaries", [])
    actual_machos = {
        file.name
        for file in scene_files
        if file.data is not None and file.data[:4] == b"\xcf\xfa\xed\xfe"
    }
    _check(r, "binary truth->disk", "five declared Mach-O binaries",
           len(binary_claims), 5)
    _check(r, "binary truth->disk", "exact Mach-O names",
           sorted(claim.get("bundle_id", "") for claim in binary_claims),
           sorted(actual_machos))
    for claim in binary_claims:
        bundle_id = claim.get("bundle_id", "")
        binary = _named(r, scene_files, bundle_id, f"binary {bundle_id}")
        if binary is None:
            continue
        data = binary.data
        if data is None:
            raise AssertionError("identity inventory did not capture file bytes")
        spans = f"disk->{bundle_id}"
        _check(r, spans, "size", len(data), claim.get("size"))
        _check(r, spans, "sha256", hashlib.sha256(data).hexdigest(), claim.get("sha256"))
        _check(r, spans, "sha1",
               hashlib.sha1(data).hexdigest(), claim.get("sha1"))      # noqa: S324 - identity
        _check(r, spans, "md5",
               hashlib.md5(data).hexdigest(), claim.get("md5"))        # noqa: S324 - identity
        _check(r, f"codesign blob->{bundle_id}", "cdhash",
               cdhash_of_file(data), claim.get("cdhash"))
        parsed = lief.parse(os.fspath(binary.path))
        undefined = sorted(
            symbol.name for symbol in parsed.symbols
            if symbol.is_external and not symbol.has_export_info
            and symbol.name.startswith("_")
        )
        _check(r, f"LIEF->{bundle_id}", "symhash",
               hashlib.md5(",".join(undefined).encode()).hexdigest(),  # noqa: S324
               claim.get("symhash"))
        _check(r, spans, "the binary is a 64-bit Mach-O",
               data[:4], b"\xcf\xfa\xed\xfe")
    tcc = _named(r, scene_files, "TCC.db", "TCC")
    knowledge = _named(r, scene_files, "knowledgeC.db", "knowledgeC")
    if tcc is not None and knowledge is not None:
        granted = {row[0] for row in _q(
            tcc, "SELECT client FROM access WHERE auth_value = 2"
        )}
        used = {row[0] for row in _q(
            knowledge,
            "SELECT ZVALUESTRING FROM ZOBJECT WHERE ZSTREAMNAME = '/app/inFocus'",
        )}
        _check(r, "TCC->knowledgeC", "exactly one granted client was also used",
               sorted(granted & used), [s["bundle_id"]])

    # Five xattr UUIDs map bijectively to five quarantine rows. URL text is opaque with
    # respect to bundle names, and agent/time are equal across candidates, so UUID is the
    # only answer-bearing row relation.
    quarantine = _named(r, scene_files, "QuarantineEventsV2", "QuarantineEventsV2")
    if quarantine is not None:
        observed_rows = _q(
            quarantine,
            "SELECT LSQuarantineEventIdentifier, LSQuarantineDataURLString, "
            "LSQuarantineAgentName, LSQuarantineTimeStamp FROM LSQuarantineEvent",
        )
        rows = {row[0]: row for row in observed_rows}
        _check(r, "QuarantineEventsV2", "five unique event UUIDs",
               len(rows), 5)
        _check(r, "QuarantineEventsV2", "one shared downloading agent",
               len({row[2] for row in observed_rows}), 1)
        _check(r, "QuarantineEventsV2", "one shared event timestamp",
               len({row[3] for row in observed_rows}), 1)

        relations = join.get("benchmark_relations", [])
        candidates = join.get("benchmark_candidates", [])
        _check(r, "benchmark truth->quarantine", "five declared relations",
               len(relations), 5)
        _check(r, "benchmark truth->quarantine", "five declared candidates",
               len(candidates), 5)
        _check(r, "benchmark candidates->QuarantineEventsV2", "candidate URL set",
               sorted(candidate.get("value", "") for candidate in candidates),
               sorted(row[1] for row in observed_rows))

        related_bundles = []
        xattr_agents = set()
        xattr_times = set()
        for index, relation in enumerate(relations):
            selector = relation.get("selector", {})
            relative_path = selector.get("xattr_relative_path")
            if not isinstance(relative_path, str):
                r.fail(
                    f"quarantine relation {index}: xattr selector is not an exact relative path"
                )
                continue
            xattr = _relative(
                r,
                scene_files,
                relative_path,
                f"quarantine relation {index}",
            )
            if xattr is None or xattr.data is None:
                continue
            try:
                parsed_xattr = parse_quarantine_xattr(xattr.data)
            except (TypeError, ValueError) as exc:
                r.fail(
                    f"quarantine relation {index}: strict xattr parser rejected "
                    f"{relative_path!r} — {type(exc).__name__}: {str(exc)[:100]}"
                )
                continue
            xattr_agents.add(parsed_xattr.agent)
            xattr_times.add(parsed_xattr.timestamp_unix)
            _check(r, "xattr->relation", "quarantine UUID",
                   parsed_xattr.event_uuid, relation.get("link_value"))
            row = rows.get(parsed_xattr.event_uuid)
            if row is None:
                r.fail(
                    "QuarantineEventsV2: relation UUID "
                    f"{parsed_xattr.event_uuid!r} matches no row"
                )
                continue
            _check(r, "xattr->QuarantineEventsV2", "download URL",
                   row[1], relation.get("expected"))
            _check(r, "xattr->QuarantineEventsV2", "downloading agent",
                   row[2], parsed_xattr.agent)
            bundle = relation.get("candidate", "")
            related_bundles.append(bundle)
            _check(r, "quarantine URL->bundle", "URL does not disclose bundle identifier",
                   str(bundle).lower() in str(row[1]).lower(), False)
        _check(r, "benchmark relations->binary candidates", "one relation per bundle",
               sorted(related_bundles), sorted(actual_machos))
        _check(r, "quarantine xattrs", "one shared downloading agent",
               len(xattr_agents), 1)
        _check(r, "quarantine xattrs", "one shared encoded timestamp",
               len(xattr_times), 1)

    plist = _named(r, scene_files, f"{s['bundle_id']}.plist", "LaunchAgent")
    if plist is not None:
        data = plist.data
        if data is None:
            raise AssertionError("identity inventory did not capture file bytes")
        pl = plistlib.loads(data)
        _check(r, "LaunchAgent->subject", "Label", pl["Label"], s["bundle_id"])
        _check(r, "LaunchAgent->subject", "program", pl["ProgramArguments"][0], s["app_path"])


def _linux_guest_to_served(home_dir: str, guest_path: str) -> str | None:
    """Gate-local transcription of the Linux loose-export mapping."""
    from pathlib import PurePosixPath

    if not isinstance(home_dir, str) or not isinstance(guest_path, str):
        return None
    path = PurePosixPath(guest_path)
    if (
        not home_dir.startswith("/")
        or not guest_path.startswith(home_dir + "/")
        or guest_path.startswith("//")
        or guest_path.endswith("/")
        or "\\" in guest_path
        or path.as_posix() != guest_path
        or any(part in {"", ".", ".."} for part in guest_path.split("/")[1:])
    ):
        return None
    return guest_path[1:]


def _linux_elf_note_marker(data: bytes) -> str | None:
    """Extract the exact synthetic marker from one ELF note without writer imports.

    Gate 3 owns the complete ELF structural profile.  Gate 2 still needs an independent,
    byte-backed derivation for the marker carried in each resident identity record, so this
    deliberately small reader walks the ELF64 little-endian section table and accepts exactly
    one ``.note.artifactforge`` note with the project's public name/type/description shape.
    """

    elf_header = struct.Struct("<16sHHIQQQIHHHHHH")
    section_header = struct.Struct("<IIQQQQIIQQ")
    if len(data) < elf_header.size or data[:7] != b"\x7fELF\x02\x01\x01":
        return None
    try:
        header = elf_header.unpack_from(data)
    except struct.error:
        return None
    section_table_offset = header[6]
    section_entry_size = header[11]
    section_count = header[12]
    string_table_index = header[13]
    if (
        section_entry_size != section_header.size
        or not 1 <= section_count <= 64
        or string_table_index >= section_count
        or section_table_offset + section_count * section_entry_size > len(data)
    ):
        return None

    try:
        sections = [
            section_header.unpack_from(data, section_table_offset + index * section_entry_size)
            for index in range(section_count)
        ]
    except struct.error:
        return None
    string_section = sections[string_table_index]
    string_offset, string_size = string_section[4], string_section[5]
    if string_section[1] != 3 or string_offset + string_size > len(data):
        return None
    names = data[string_offset:string_offset + string_size]

    def section_name(section: tuple[int, ...]) -> bytes | None:
        offset = section[0]
        if offset >= len(names):
            return None
        end = names.find(b"\x00", offset)
        return None if end < 0 else names[offset:end]

    matches = [
        section
        for section in sections
        if section[1] == 7 and section_name(section) == b".note.artifactforge"
    ]
    if len(matches) != 1:
        return None
    note_offset, note_size = matches[0][4], matches[0][5]
    if note_offset + note_size > len(data):
        return None
    note = data[note_offset:note_offset + note_size]
    if len(note) < 12:
        return None
    try:
        name_size, description_size, note_type = struct.unpack_from("<III", note)
    except struct.error:
        return None
    name_start = 12
    name_end = name_start + name_size
    description_start = (name_end + 3) & ~3
    description_end = description_start + description_size
    note_end = (description_end + 3) & ~3
    if (
        note_end != len(note)
        or note_type != 0xAF01
        or note[name_start:name_end] != b"ArtifactForge\x00"
        or any(note[name_end:description_start])
        or any(note[description_end:note_end])
    ):
        return None
    description = note[description_start:description_end]
    prefix = b"ARTIFACTFORGE-SYNTHETIC-"
    suffix = description[len(prefix):]
    if (
        not description.startswith(prefix)
        or len(suffix) != 16
        or any(character not in b"0123456789abcdef" for character in suffix)
    ):
        return None
    return description.decode("ascii")


def _linux(r: GateReport, scene_files: tuple[InventoryFile, ...], join: dict) -> None:
    """Re-derive the XDG/history/ELF thread from exact recursive paths and bytes."""
    from artifactforge.gates.oracles import load_bash_history, load_desktop_entry

    home_dir = join.get("home_dir")
    residents = join.get("residents")
    subject = join.get("subject")
    autostart = join.get("autostart")
    history_claim = join.get("bash_history")
    if (
        not isinstance(home_dir, str)
        or not isinstance(residents, list)
        or not isinstance(subject, dict)
        or not isinstance(autostart, list)
        or not isinstance(history_claim, dict)
    ):
        r.fail("linux join: required home/resident/subject/autostart/history records are malformed")
        return

    history_served = history_claim.get("served_relpath")
    declared_scene_paths = [
        record.get("served_relpath")
        for records in (residents, autostart)
        for record in records
        if isinstance(record, dict) and isinstance(record.get("served_relpath"), str)
    ]
    if isinstance(history_served, str):
        declared_scene_paths.append(history_served)
    _check(
        r,
        "declared Linux scene->served tree",
        "exact complete artifact inventory",
        sorted(file.relative_path for file in scene_files),
        sorted(declared_scene_paths),
    )

    actual_elf = {
        file.relative_path: file
        for file in scene_files
        if file.data is not None and file.data[:4] == b"\x7fELF"
    }
    declared_paths = [
        record.get("served_relpath")
        for record in residents
        if isinstance(record, dict)
    ]
    _check(
        r,
        "join inventory->disk",
        "resident ELF served paths",
        sorted(actual_elf),
        declared_paths,
    )

    guest_to_record: dict[str, dict] = {}
    for index, record in enumerate(residents):
        if not isinstance(record, dict):
            r.fail(f"linux join: resident record {index} is not an object")
            continue
        guest = record.get("guest_path")
        served = record.get("served_relpath")
        if not isinstance(guest, str) or not isinstance(served, str):
            r.fail(f"linux join: resident record {index} has malformed paths")
            continue
        expected_served = _linux_guest_to_served(home_dir, guest)
        _check(
            r,
            "guest namespace->served tree",
            f"exact path mapping for {guest}",
            served,
            expected_served,
        )
        if guest in guest_to_record:
            r.fail(f"linux join: duplicate resident guest path {guest!r}")
        guest_to_record[guest] = record
        file = _relative(r, scene_files, served, "resident ELF")
        if file is None or file.data is None:
            continue
        _check(
            r,
            f"disk->{record.get('role', 'resident')}",
            "name",
            file.name,
            record.get("name"),
        )
        _check(
            r,
            f"disk->{record.get('role', 'resident')}",
            "sha256",
            hashlib.sha256(file.data).hexdigest(),
            record.get("sha256"),
        )
        _check(
            r,
            f"disk->{record.get('role', 'resident')}",
            "sha1",
            hashlib.sha1(file.data).hexdigest(),  # noqa: S324 - forensic identity
            record.get("sha1"),
        )
        _check(
            r,
            f"disk->{record.get('role', 'resident')}",
            "md5",
            hashlib.md5(file.data).hexdigest(),  # noqa: S324 - forensic identity
            record.get("md5"),
        )
        _check(
            r,
            f"ELF note->{record.get('role', 'resident')}",
            "marker",
            _linux_elf_note_marker(file.data),
            record.get("marker"),
        )

    desktop_exec_by_path = {}
    actual_desktop_paths = []
    for file in scene_files:
        if not file.relative_path.endswith(".desktop"):
            continue
        actual_desktop_paths.append(file.relative_path)
        try:
            desktop_exec_by_path[file.relative_path] = load_desktop_entry(file.path).exec_path
        except Exception as exc:  # Gate 1 owns detailed parser refusal; Gate 2 must still fail.
            r.fail(
                f"{file.relative_path}: cannot derive XDG Exec for identity — "
                f"{type(exc).__name__}: {str(exc)[:100]}"
            )
    declared_desktop_exec_by_path = {
        record.get("served_relpath"): record.get("exec_guest_path")
        for record in autostart
        if isinstance(record, dict)
        and isinstance(record.get("served_relpath"), str)
        and isinstance(record.get("exec_guest_path"), str)
    }
    declared_desktop_paths = sorted(
        record.get("served_relpath")
        for record in autostart
        if isinstance(record, dict) and isinstance(record.get("served_relpath"), str)
    )
    _check(
        r,
        "join inventory->XDG autostart",
        "exact desktop-entry served paths",
        sorted(actual_desktop_paths),
        declared_desktop_paths,
    )
    for index, record in enumerate(autostart):
        if not isinstance(record, dict):
            r.fail(f"linux join: autostart record {index} is not an object")
            continue
        _check(
            r,
            "XDG guest namespace->served tree",
            f"exact path mapping for autostart record {index}",
            record.get("served_relpath"),
            _linux_guest_to_served(home_dir, record.get("guest_path")),
        )
    _check(
        r,
        "XDG autostart->resident ELF",
        "exact per-file Exec mapping",
        sorted(desktop_exec_by_path.items()),
        sorted(declared_desktop_exec_by_path.items()),
    )
    desktop_execs = list(desktop_exec_by_path.values())
    nonresident_desktop = sorted(set(desktop_execs) - set(guest_to_record))
    _check(
        r,
        "XDG autostart->resident ELF",
        "every Exec target is resident",
        nonresident_desktop,
        [],
    )

    actual_history_paths = sorted(
        file.relative_path for file in scene_files if file.name == ".bash_history"
    )
    declared_history_paths = [history_served] if isinstance(history_served, str) else []
    _check(
        r,
        "join inventory->Bash history",
        "exact history served paths",
        actual_history_paths,
        declared_history_paths,
    )
    history_commands = []
    direct_history = []
    if isinstance(history_served, str):
        history_file = _relative(r, scene_files, history_served, "Bash history")
        if history_file is not None:
            try:
                entries = load_bash_history(
                    history_file.path,
                    resident_paths=sorted(guest_to_record),
                )
                history_commands = [entry.command for entry in entries]
                direct_history = [command for command in history_commands if command.startswith("/")]
            except Exception as exc:
                r.fail(
                    f"{history_served}: cannot derive Bash commands for identity — "
                    f"{type(exc).__name__}: {str(exc)[:100]}"
                )
    else:
        r.fail("linux join: Bash history served path is malformed")
    _check(
        r,
        "Bash guest namespace->served tree",
        "exact history path mapping",
        history_served,
        _linux_guest_to_served(home_dir, history_claim.get("guest_path")),
    )
    expected_history = history_claim.get("direct_exec_guest_paths")
    observed_history_profile = (
        len(history_commands),
        history_commands[0] if history_commands else None,
        tuple(command for command in history_commands if not command.startswith("/")),
        sorted(direct_history),
    )
    expected_history_profile = (
        4,
        _LINUX_HISTORY_MARKER,
        (_LINUX_HISTORY_MARKER,),
        expected_history,
    )
    _check(
        r,
        "Bash history->declared join",
        "exact four-record scene profile",
        observed_history_profile,
        expected_history_profile,
    )
    _check(
        r,
        "Bash history->resident ELF",
        "exact direct-execution target set",
        sorted(direct_history),
        expected_history,
    )
    _check(
        r,
        "Bash history->resident ELF",
        "every direct command names a resident",
        sorted(set(direct_history) - set(guest_to_record)),
        [],
    )

    observed_subjects = sorted(set(desktop_execs) & set(direct_history))
    subject_guest = subject.get("guest_path")
    _check(
        r,
        "XDG autostart->Bash history->resident ELF",
        "unique shared subject",
        observed_subjects,
        [subject_guest],
    )
    declared_subject_record = guest_to_record.get(subject_guest)
    _check(
        r,
        "shared subject->resident identity",
        "subject record",
        subject,
        declared_subject_record,
    )


def run(scene_dir: str, join: dict) -> GateReport:
    r = GateReport(2, "identity",
                   "do the declared answer-bearing pivots agree with emitted bytes?")
    try:
        with captured_regular_tree(scene_dir) as scene_files:
            if not scene_files:
                r.fail(
                    f"no artifact in {scene_dir!r} was inventoried, so no identity pivot was checked"
                )
            elif join.get("family") == "windows":
                _windows(r, scene_files, join)
            elif join.get("family") == "macos":
                _macos(r, scene_files, join)
            elif join.get("family") == "linux":
                _linux(r, scene_files, join)
            else:
                r.fail(f"scene family {join.get('family')!r} has no identity gate implementation")
    except InventoryError as exc:
        r.fail(f"scene inventory is unsafe: {exc}")
    joined = r.metrics.get("checks_joined", 0)
    total = r.metrics.get("checks_total", 0)
    r.denominator = f"{joined}/{total} cross-artifact identity checks hold"
    return r
