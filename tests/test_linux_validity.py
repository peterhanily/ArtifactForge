# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 1 Linux parser consensus, exact profiles, and bounded text snapshots."""
from __future__ import annotations

from pathlib import Path
import struct

import pytest

from artifactforge.compose import build_linux_scene
from artifactforge.content import ContentStore, build_elf
from artifactforge.gates import validity
from artifactforge.model import linux_profile


pytest.importorskip("lief")
pytest.importorskip("elftools.elf.elffile")
pytest.importorskip("xdg.DesktopEntry")
pytest.importorskip("dissect.target")


def _build(root: Path):
    (root / "scenes").mkdir(parents=True)
    return build_linux_scene(
        ContentStore("linux-validity-test", str(root / "content")),
        skey=b"v" * 32,
        profile=linux_profile(hostname="linux-validity", username="v"),
        scene_dir=str(root / "scenes" / "one"),
        staging_dir=str(root / "staging"),
    )


def _new_failures(before, after):
    return set(after.fails) - set(before.fails)


def _replace_desktop_value(path: Path, key: str, value: str) -> None:
    prefix = f"{key}=".encode()
    lines = path.read_bytes().splitlines(keepends=True)
    matches = [index for index, line in enumerate(lines) if line.startswith(prefix)]
    assert len(matches) == 1
    lines[matches[0]] = prefix + value.encode("utf-8") + b"\n"
    path.write_bytes(b"".join(lines))


def _mutate_scene_history(scene, mutation: str) -> None:
    path = Path(scene.directory) / scene.join["bash_history"]["served_relpath"]
    lines = path.read_text(encoding="ascii").splitlines()
    assert len(lines) == 8
    if mutation == "changed-marker":
        lines[1] = ": 'ARTIFACTFORGE-SYNTHETIC-ALTERED'"
    elif mutation == "extra-marker":
        lines.extend((f"#{int(lines[-2][1:]) + 1}", ": 'ARTIFACTFORGE-SYNTHETIC-EXTRA'"))
    elif mutation == "missing-marker":
        lines = lines[2:]
    elif mutation == "duplicate-direct":
        lines[5] = lines[3]
    elif mutation == "extra-record":
        direct = set(scene.join["bash_history"]["direct_exec_guest_paths"])
        extra = next(
            resident["guest_path"]
            for resident in scene.join["residents"]
            if resident["guest_path"] not in direct
        )
        lines.extend((f"#{int(lines[-2][1:]) + 1}", extra))
    else:  # pragma: no cover - the parametrization is closed.
        raise AssertionError(mutation)
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def test_linux_scene_has_two_typed_reads_and_two_semantic_checks_per_artifact(tmp_path):
    scene = _build(tmp_path)
    report = validity.run(scene.directory)

    assert report.ok, report.render()
    assert report.metrics == {
        "oracle_reads_passed": 18,
        "oracle_reads_total": 18,
        "semantic_checks_passed": 18,
        "semantic_checks_total": 18,
        "claim_scopes": {
            "container_acceptance": {"passed": 18, "total": 18},
            "semantic_extraction": {"passed": 18, "total": 18},
            "independent_consensus": {"passed": 9, "total": 9},
            "declared_profile_conformance": {"passed": 9, "total": 9},
            "downstream_consumer_compatibility": {"passed": 0, "total": 0},
        },
    }
    assert validity.classify_bytes(b"\x7fELF", "anything") == "elf"
    assert validity.classify_bytes(b"text", "entry.desktop") == "desktop-entry"
    assert validity.classify_bytes(b"text", "/home/v/.bash_history") == "bash-history"


def test_parseable_elf_entry_mutation_preserves_consensus_but_fails_exact_profile(tmp_path):
    scene = _build(tmp_path)
    before = validity.run(scene.directory)
    resident = Path(scene.directory) / scene.join["residents"][0]["served_relpath"]
    data = bytearray(resident.read_bytes())
    struct.pack_into("<Q", data, 24, 0x1001)
    resident.write_bytes(data)

    after = validity.run(scene.directory)
    failures = _new_failures(before, after)
    assert not after.ok
    assert after.metrics["oracle_reads_passed"] == 18
    assert after.metrics["semantic_checks_passed"] == 17
    assert any("linux-elf-profile" in failure for failure in failures)
    assert not any("elf-consensus" in failure for failure in failures)


def test_parseable_elf_instruction_mutation_is_seen_by_both_parsers_and_profile(tmp_path):
    scene = _build(tmp_path)
    resident = Path(scene.directory) / scene.join["residents"][0]["served_relpath"]
    data = bytearray(resident.read_bytes())
    data[0x1000] ^= 0x01
    resident.write_bytes(data)

    report = validity.run(scene.directory)
    assert not report.ok
    # Both independent parsers still agree on the changed section bytes; the fixed semantic
    # profile, rather than a parse exception, is what rejects the mutation.
    assert report.metrics["oracle_reads_passed"] == 18
    assert report.metrics["semantic_checks_passed"] == 17
    assert any("direct-exit entry body" in failure for failure in report.fails)


def test_xdg_path_mutation_is_parser_valid_but_outside_autostart_profile(tmp_path):
    scene = _build(tmp_path)
    before = validity.run(scene.directory)
    source = Path(scene.directory) / scene.join["autostart"][0]["served_relpath"]
    destination = source.parents[1] / "not-autostart" / source.name
    destination.parent.mkdir()
    source.rename(destination)

    after = validity.run(scene.directory)
    failures = _new_failures(before, after)
    assert not after.ok
    assert after.metrics["oracle_reads_passed"] == 18
    assert after.metrics["semantic_checks_passed"] == 17
    assert any("xdg-autostart-profile" in failure for failure in failures)
    assert not any("desktop-entry-consensus" in failure for failure in failures)


def test_xdg_name_and_comment_accept_exact_utf8_byte_boundaries(tmp_path):
    scene = _build(tmp_path)
    source = Path(scene.directory) / scene.join["autostart"][0]["served_relpath"]
    _replace_desktop_value(source, "Name", "é" * 128)
    _replace_desktop_value(source, "Comment", "é" * 512)

    report = validity.run(scene.directory)

    assert report.ok, report.render()
    assert report.metrics["oracle_reads_passed"] == 18
    assert report.metrics["semantic_checks_passed"] == 18


@pytest.mark.parametrize(
    ("key", "value", "limit"),
    [
        ("Name", "é" * 128 + "a", 256),
        ("Comment", "é" * 512 + "a", 1024),
    ],
)
def test_xdg_parser_valid_utf8_value_overflow_fails_exact_profile(
    tmp_path, key, value, limit
):
    scene = _build(tmp_path)
    source = Path(scene.directory) / scene.join["autostart"][0]["served_relpath"]
    _replace_desktop_value(source, key, value)

    report = validity.run(scene.directory)

    assert not report.ok
    assert report.metrics["oracle_reads_passed"] == 18
    assert report.metrics["semantic_checks_passed"] == 17
    assert any(
        f"XDG autostart {key} exceeds the {limit}-byte profile limit" in failure
        for failure in report.fails
    )
    assert not any("desktop-entry-consensus" in failure for failure in report.fails)


def test_bash_allowlist_is_derived_only_from_recursive_elf_served_paths(tmp_path):
    scene = _build(tmp_path)
    before = validity.run(scene.directory)
    history = Path(scene.directory) / scene.join["bash_history"]["served_relpath"]
    resident = scene.join["bash_history"]["direct_exec_guest_paths"][0]
    data = history.read_bytes().replace(
        resident.encode(),
        b"/home/v/.local/bin/not-a-resident",
        1,
    )
    history.write_bytes(data)

    after = validity.run(scene.directory)
    failures = _new_failures(before, after)
    assert not after.ok
    assert after.metrics["oracle_reads_passed"] == 17
    assert any("bash-history-raw rejected" in failure for failure in failures)
    assert any("not an exact resident path" in failure for failure in failures)


@pytest.mark.parametrize(
    "mutation",
    ("changed-marker", "extra-marker", "missing-marker", "duplicate-direct", "extra-record"),
)
def test_bash_parsers_accept_but_exact_linux_scene_profile_rejects_history_shape_mutations(
    tmp_path, mutation
):
    scene = _build(tmp_path)
    _mutate_scene_history(scene, mutation)

    report = validity.run(scene.directory)

    assert not report.ok
    assert report.metrics["oracle_reads_passed"] == 18
    assert report.metrics["oracle_reads_total"] == 18
    assert report.metrics["semantic_checks_passed"] == 17
    assert report.metrics["semantic_checks_total"] == 18
    assert any("bash-history-profile" in failure for failure in report.fails)
    assert not any("bash-history-consensus" in failure for failure in report.fails)


def test_structured_magic_cannot_hide_behind_plain_sidecar_suffix(tmp_path):
    scene = _build(tmp_path)
    disguised = Path(scene.directory) / "payload.json"
    disguised.write_bytes(b"SQLite format 3\x00ARTIFACTFORGE")

    report = validity.run(scene.directory)

    assert not report.ok
    assert report.metrics["oracle_reads_total"] == 20
    assert report.metrics["oracle_reads_passed"] == 18
    assert any("sqlite3 rejected" in failure for failure in report.fails)
    assert any("sqlite-raw rejected" in failure for failure in report.fails)


def test_elf_magic_still_runs_both_oracles_when_named_as_text(tmp_path):
    scene = _build(tmp_path)
    resident = Path(scene.directory) / scene.join["residents"][0]["served_relpath"]
    (Path(scene.directory) / "payload.txt").write_bytes(resident.read_bytes())

    report = validity.run(scene.directory)

    assert not report.ok
    assert report.metrics == {
        "oracle_reads_passed": 20,
        "oracle_reads_total": 20,
        "semantic_checks_passed": 19,
        "semantic_checks_total": 20,
        "claim_scopes": {
            "container_acceptance": {"passed": 20, "total": 20},
            "semantic_extraction": {"passed": 20, "total": 20},
            "independent_consensus": {"passed": 10, "total": 10},
            "declared_profile_conformance": {"passed": 9, "total": 10},
            "downstream_consumer_compatibility": {"passed": 0, "total": 0},
        },
    }
    assert any("Linux ELF must be served" in failure for failure in report.fails)


def test_oversized_bash_snapshot_fails_before_either_text_parser_runs(monkeypatch, tmp_path):
    scene = tmp_path / "scene"
    resident = scene / "home/v/.local/bin/helper"
    history = scene / "home/v/.bash_history"
    resident.parent.mkdir(parents=True)
    resident.write_bytes(build_elf(b"bounded-snapshot"))
    history.write_bytes(b"x" * (1024 * 1024 + 1))

    def should_not_run(_source):
        raise AssertionError("oversized text reached a parser")

    monkeypatch.setitem(validity.READERS, "dissect.target", should_not_run)
    monkeypatch.setitem(validity.READERS, "bash-history-raw", should_not_run)
    report = validity.run(str(scene))

    assert not report.ok
    assert report.metrics["oracle_reads_passed"] == 2
    assert report.metrics["oracle_reads_total"] == 4
    assert any("1048576-byte snapshot limit" in failure for failure in report.fails)
    assert not any("AssertionError" in failure for failure in report.fails)


def test_dissect_adapter_uses_public_bashhistory_surface():
    source = Path(validity.__file__).read_text()
    start = source.index("def _read_dissect_bash_history")
    end = source.index("\ndef _read_bash_history_raw", start)
    adapter = source[start:end]
    assert "target.bashhistory()" in adapter
    assert "parse_generic_history" not in adapter
