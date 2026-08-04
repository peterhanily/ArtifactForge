# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 1 consensus, resource and macOS semantic-profile regressions."""
from __future__ import annotations

import dataclasses
from pathlib import Path
import struct

import pytest

from artifactforge import suite
from artifactforge.compose.scene import build_macos_scene
from artifactforge.content import ContentStore
from artifactforge.gates import inertness, validity
from artifactforge.model import macos_profile

pytest.importorskip("lief")
pytest.importorskip("macholib")


def _scene(tmp_path, name="scene"):
    key = suite.scenario_key(suite.PUBLIC_DEV_KEY, f"phase3::{name}")
    root = tmp_path / name
    return build_macos_scene(
        ContentStore(f"phase3::{name}", str(root / "content")),
        skey=key,
        profile=macos_profile(),
        scene_dir=str(root / "scene"),
        staging_dir=str(root / "staging"),
    )


def _new_fails(before, after):
    return [failure for failure in after.fails if failure not in before.fails]


def test_macos_gate_has_two_reads_plus_profile_consensus_and_sqlite_queries(tmp_path):
    task = _scene(tmp_path)
    report = validity.run(task.directory)
    assert report.ok, report.render()
    assert not report.gaps
    assert report.metrics == {
        "oracle_reads_passed": 32,
        "oracle_reads_total": 32,
        "semantic_checks_passed": 35,
        "semantic_checks_total": 35,
        "claim_scopes": {
            "container_acceptance": {"passed": 32, "total": 32},
            "semantic_extraction": {"passed": 32, "total": 32},
            "independent_consensus": {"passed": 16, "total": 16},
            "declared_profile_conformance": {"passed": 16, "total": 16},
            "downstream_consumer_compatibility": {"passed": 3, "total": 3},
        },
    }


def test_each_parser_pair_receives_the_same_immutable_snapshot_object(tmp_path, monkeypatch):
    task = _scene(tmp_path, "snapshots")
    observed = {"sqlite": [], "plist": [], "quarantine-xattr": []}
    originals = {
        name: validity.READERS[name]
        for name in (
            "sqlite3",
            "sqlite-raw",
            "plistlib",
            "bplist-raw",
            "macos-xattr",
            "quarantine-xattr-raw",
        )
    }

    def recording(kind, name):
        def read(source):
            assert type(source) is bytes
            observed[kind].append((name, source))
            return originals[name](source)

        return read

    for name in ("sqlite3", "sqlite-raw"):
        monkeypatch.setitem(validity.READERS, name, recording("sqlite", name))
    for name in ("plistlib", "bplist-raw"):
        monkeypatch.setitem(validity.READERS, name, recording("plist", name))
    for name in ("macos-xattr", "quarantine-xattr-raw"):
        monkeypatch.setitem(
            validity.READERS,
            name,
            recording("quarantine-xattr", name),
        )

    report = validity.run(task.directory)
    assert report.ok, report.render()
    for records in observed.values():
        assert len(records) % 2 == 0
        for first, second in zip(records[::2], records[1::2], strict=True):
            assert first[1] is second[1]


def test_oversized_plist_is_rejected_before_either_parser_runs(tmp_path, monkeypatch):
    scene = tmp_path / "oversized"
    scene.mkdir()
    (scene / "too-large.plist").write_bytes(b"bplist00" + b"\x00" * (1024 * 1024))
    called = []

    def should_not_run(_source):
        called.append(True)
        raise AssertionError("bounded pre-snapshot should have stopped this reader")

    monkeypatch.setitem(validity.READERS, "plistlib", should_not_run)
    monkeypatch.setitem(validity.READERS, "bplist-raw", should_not_run)
    report = validity.run(str(scene))
    assert not called
    assert report.metrics["oracle_reads_passed"] == 0
    assert report.metrics["oracle_reads_total"] == 2
    assert sum("snapshot limit" in failure for failure in report.fails) == 2


def _shared_dag_plist() -> bytes:
    width = 4096
    objects = [
        b"\xaf\x11\x10\x00" + bytes([child]) * width for child in (1, 2, 3, 4)
    ] + [b"\x09"]
    offsets = []
    cursor = 8
    for item in objects:
        offsets.append(cursor)
        cursor += len(item)
    data = (
        b"bplist00"
        + b"".join(objects)
        + b"".join(value.to_bytes(2, "big") for value in offsets)
        + b"\x00" * 6
        + b"\x02\x01"
        + struct.pack(">QQQ", 5, 0, cursor)
    )
    assert len(data) == 16_451
    return data


@pytest.mark.parametrize("reader", [validity._read_plistlib, validity._read_bplist_raw])
def test_shared_container_dag_is_rejected_without_logical_expansion(reader):
    with pytest.raises(validity.SemanticError, match="node validation limit|reuses a container"):
        reader(_shared_dag_plist())


def test_typed_observation_node_limit_is_exact():
    assert validity._typed_value([None] * 255)[0] == "array"
    with pytest.raises(validity.SemanticError, match="256-node"):
        validity._typed_value([None] * 256)


def test_injected_raw_sqlite_observation_cannot_earn_consensus(tmp_path, monkeypatch):
    task = _scene(tmp_path, "altered-observation")
    before = validity.run(task.directory)
    assert before.ok
    original = validity.READERS["sqlite-raw"]

    def altered(source):
        view = original(source)
        first = view.schema[0]
        return dataclasses.replace(view, schema=((first[0], *first[1:4], 99, first[5]), *view.schema[1:]))

    monkeypatch.setitem(validity.READERS, "sqlite-raw", altered)
    new = _new_fails(before, validity.run(task.directory))
    assert any("sqlite-consensus" in failure for failure in new), new


def test_invalid_reader_result_shape_is_not_counted_as_a_pass(tmp_path, monkeypatch):
    task = _scene(tmp_path, "shape")
    monkeypatch.setitem(validity.READERS, "sqlite-raw", lambda _source: "looks plausible")
    report = validity.run(task.directory)
    assert report.metrics["oracle_reads_passed"] == 29
    assert report.metrics["oracle_reads_total"] == 32
    assert any("invalid observation shape" in failure for failure in report.fails)


def test_quarantine_xattr_consensus_is_type_exact(tmp_path, monkeypatch):
    task = _scene(tmp_path, "xattr-types")
    before = validity.run(task.directory)
    assert before.ok
    original = validity.READERS["quarantine-xattr-raw"]

    def altered(source):
        view = original(source)
        return dataclasses.replace(view, timestamp_unix=True)

    monkeypatch.setitem(validity.READERS, "quarantine-xattr-raw", altered)
    after = validity.run(task.directory)
    new = _new_fails(before, after)
    assert any("quarantine-xattr-consensus" in failure for failure in new), new
    assert after.metrics["oracle_reads_passed"] == after.metrics["oracle_reads_total"]


@pytest.mark.parametrize(
    "mutate",
    (
        lambda data: data + b"\n",
        lambda data: data[:-36] + data[-36:].lower(),
        lambda data: b"0081" + data[4:],
        lambda data: data[:5] + b"A" + data[6:],
        lambda data: data + b";extra",
    ),
    ids=("newline", "lowercase-uuid", "wrong-flags", "uppercase-time", "extra-field"),
)
def test_noncanonical_quarantine_xattr_is_gate1_red(tmp_path, mutate):
    task = _scene(tmp_path, "xattr-profile")
    before = validity.run(task.directory)
    assert before.ok, before.render()
    relative_path = task.join["benchmark_relations"][0]["selector"]["xattr_relative_path"]
    path = Path(task.directory) / relative_path
    path.write_bytes(mutate(path.read_bytes()))

    after = validity.run(task.directory)
    new = _new_fails(before, after)
    assert not after.ok
    assert any(
        "macos-xattr rejected" in failure
        or "quarantine-xattr-raw rejected" in failure
        for failure in new
    ), new


def test_only_a_strict_quarantine_xattr_earns_the_gate3_marker_exemption(tmp_path):
    value = b"0181;65920080;Safari;01234567-89AB-4CDE-8F01-23456789ABCD"

    exact = tmp_path / "exact"
    exact.mkdir()
    (exact / "sample.quarantine.xattr").write_bytes(value)
    gate1 = validity.run(str(exact))
    gate3 = inertness.run(str(exact))
    assert gate1.ok, gate1.render()
    assert gate3.ok, gate3.render()
    assert gate3.metrics["formats_total"] == 0

    malformed = tmp_path / "malformed"
    malformed.mkdir()
    (malformed / "sample.quarantine.xattr").write_bytes(value + b"\n")
    gate1 = validity.run(str(malformed))
    gate3 = inertness.run(str(malformed))
    assert not gate1.ok
    assert not gate3.ok
    assert any("cannot use the synthetic-marker exemption" in failure for failure in gate3.fails)

    other_format = tmp_path / "other-format"
    other_format.mkdir()
    (other_format / "sample.desktop").write_bytes(value)
    gate3 = inertness.run(str(other_format))
    assert not gate3.ok
    assert any("desktop-entry carries no in-band synthetic marker" in failure for failure in gate3.fails)

    unclassified = tmp_path / "unclassified"
    unclassified.mkdir()
    (unclassified / "sample.bin").write_bytes(value)
    assert not validity.run(str(unclassified)).ok
    assert not inertness.run(str(unclassified)).ok


def test_quarantine_control_byte_is_profile_red_while_both_readers_stay_green(tmp_path):
    task = _scene(tmp_path, "url-control")
    before = validity.run(task.directory)
    assert before.ok
    path = Path(task.directory) / "QuarantineEventsV2"
    data = bytearray(path.read_bytes())
    start = data.index(b"https://")
    target = data.index(b".", start)
    data[target] = 0x0A
    path.write_bytes(data)

    after = validity.run(task.directory)
    new = _new_fails(before, after)
    assert any("sqlite-profile" in failure for failure in new), new
    assert not any("sqlite-consensus" in failure or "rejected it" in failure for failure in new)


def test_huge_finite_sqlite_real_is_outside_the_exact_writer_profile(tmp_path):
    import sqlite3
    from artifactforge.disclosure import MARKER, NOTICE, RESERVED_NAME

    task = _scene(tmp_path, "huge-real")
    before = validity.run(task.directory)
    assert before.ok
    path = Path(task.directory) / "knowledgeC.db"
    source = sqlite3.connect(path)
    try:
        bundles = [row[0] for row in source.execute(
            "SELECT ZVALUESTRING FROM ZOBJECT ORDER BY Z_PK"
        )]
    finally:
        source.close()
    replacement = path.with_name("knowledgeC.replacement")
    con = sqlite3.connect(replacement)
    try:
        con.execute("PRAGMA page_size=4096")
        con.execute(
            "CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME TEXT, "
            "ZVALUESTRING TEXT, ZSTARTDATE REAL, ZENDDATE REAL)"
        )
        for rowid, bundle in enumerate(bundles, 1):
            start = 1e100 if rowid == 1 else float(rowid * 100)
            con.execute(
                "INSERT INTO ZOBJECT VALUES (?, '/app/inFocus', ?, ?, ?)",
                (rowid, bundle, start, start + 1e99 if rowid == 1 else start + 1.0),
            )
        con.execute(f"CREATE TABLE {RESERVED_NAME} (marker TEXT, notice TEXT)")
        con.execute(f"INSERT INTO {RESERVED_NAME} VALUES (?, ?)", (MARKER, NOTICE))
        con.commit()
    finally:
        con.close()
    replacement.replace(path)

    after = validity.run(task.directory)
    new = _new_fails(before, after)
    assert any("sqlite-profile" in failure for failure in new), new
    assert not any("sqlite-consensus" in failure or "rejected it" in failure for failure in new)


def test_launchagent_control_byte_is_profile_red_while_both_readers_stay_green(tmp_path):
    task = _scene(tmp_path, "path-control")
    before = validity.run(task.directory)
    assert before.ok
    subject = task.join["subject"]
    path = Path(task.directory) / f"{subject['bundle_id']}.plist"
    data = bytearray(path.read_bytes())
    program = subject["app_path"].encode("ascii")
    start = data.index(program)
    data[start + program.index(b"/") + 1] = 0x0A
    path.write_bytes(data)

    after = validity.run(task.directory)
    new = _new_fails(before, after)
    assert any("launchagent-profile" in failure for failure in new), new
    assert not any("bplist-consensus" in failure or "rejected it" in failure for failure in new)
