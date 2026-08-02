# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Linux loose scenes bind real recursive paths without entering the invalid benchmark."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import struct

import pytest

from artifactforge.compose import build_linux_scene
from artifactforge.content import ContentStore
from artifactforge.gates import identity
from artifactforge.gates.inertness import _elf_code_is_inert
from artifactforge.gates.oracles import load_bash_history, load_desktop_entry
from artifactforge.inventory import inventory_regular_files
from artifactforge.model import linux_profile


def _build(root: Path, *, key: bytes = b"l" * 32):
    (root / "scenes").mkdir(parents=True)
    return build_linux_scene(
        ContentStore("linux-scene-test", str(root / "content")),
        skey=key,
        profile=linux_profile(hostname="linux-101", username="v"),
        scene_dir=str(root / "scenes" / "one"),
        staging_dir=str(root / "staging"),
    )


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


def test_linux_scene_has_exact_recursive_evidence_thread(tmp_path):
    scene = _build(tmp_path)
    files = inventory_regular_files(scene.directory, capture_bytes=True)
    assert scene.family == scene.join["family"] == "linux"
    assert len(files) == len(scene.artifacts) == 9
    assert [file.relative_path for file in files] == scene.artifacts
    assert sum(file.data[:4] == b"\x7fELF" for file in files) == 5
    assert sum(file.relative_path.endswith(".desktop") for file in files) == 3
    assert sum(file.name == ".bash_history" for file in files) == 1

    residents = scene.join["residents"]
    assert len(residents) == 5
    assert residents == sorted(residents, key=lambda item: item["served_relpath"])
    for resident in residents:
        assert resident["served_relpath"] == resident["guest_path"][1:]
        data = (Path(scene.directory) / resident["served_relpath"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == resident["sha256"]
        assert hashlib.sha1(data).hexdigest() == resident["sha1"]  # noqa: S324
        assert _elf_code_is_inert(data)[0]

    desktop_targets = {
        load_desktop_entry(file.path).exec_path
        for file in files
        if file.relative_path.endswith(".desktop")
    }
    history_file = next(file for file in files if file.name == ".bash_history")
    history = load_bash_history(
        history_file.path,
        resident_paths=[resident["guest_path"] for resident in residents],
    )
    history_targets = {entry.command for entry in history if entry.command.startswith("/")}
    assert desktop_targets & history_targets == {scene.join["subject"]["guest_path"]}
    assert any(entry.command.startswith(": 'ARTIFACTFORGE-SYNTHETIC-") for entry in history)


def test_linux_scene_is_byte_deterministic(tmp_path):
    first = _build(tmp_path / "first")
    second = _build(tmp_path / "second")
    first_files = inventory_regular_files(first.directory, capture_bytes=True)
    second_files = inventory_regular_files(second.directory, capture_bytes=True)
    assert [(file.relative_path, file.data) for file in first_files] == [
        (file.relative_path, file.data) for file in second_files
    ]
    assert first.join == second.join


def test_linux_identity_rederives_the_exact_path_join(tmp_path):
    scene = _build(tmp_path)
    report = identity.run(scene.directory, scene.join)
    assert report.ok, report.render()
    assert report.metrics == {"checks_total": 45, "checks_joined": 45}


@pytest.mark.parametrize(
    "mutation",
    ("changed-marker", "extra-marker", "missing-marker", "duplicate-direct", "extra-record"),
)
def test_linux_identity_cannot_false_pass_an_out_of_profile_history(
    tmp_path, mutation
):
    scene = _build(tmp_path)
    _mutate_scene_history(scene, mutation)

    report = identity.run(scene.directory, scene.join)

    assert not report.ok
    assert report.metrics["checks_total"] == 45
    assert report.metrics["checks_joined"] < 45
    assert any("exact four-record scene profile" in reason for reason in report.fails)


@pytest.mark.parametrize(
    ("relative_path", "data"),
    ((".hidden.json", b"{}\n"), ("home/v/.cache/unclassified", b"opaque\n")),
)
def test_linux_identity_requires_the_exact_complete_declared_inventory(
    tmp_path, relative_path, data
):
    scene = _build(tmp_path)
    extra = Path(scene.directory) / relative_path
    extra.parent.mkdir(parents=True, exist_ok=True)
    extra.write_bytes(data)

    report = identity.run(scene.directory, scene.join)

    assert not report.ok
    assert report.metrics == {"checks_total": 45, "checks_joined": 44}
    assert any("exact complete artifact inventory" in reason for reason in report.fails)


def test_linux_identity_reddens_when_an_xdg_exec_target_changes(tmp_path):
    scene = _build(tmp_path)
    subject_path = scene.join["subject"]["guest_path"]
    replacement = scene.join["bash_history"]["direct_exec_guest_paths"][1]
    desktop = next(
        Path(scene.directory) / record["served_relpath"]
        for record in scene.join["autostart"]
        if record["exec_guest_path"] == subject_path
    )
    original = desktop.read_bytes()
    desktop.write_bytes(original.replace(subject_path.encode(), replacement.encode()))
    report = identity.run(scene.directory, scene.join)
    assert not report.ok
    assert any("XDG autostart" in reason for reason in report.fails)


def test_linux_identity_binds_each_declared_xdg_exec_to_its_served_file(tmp_path):
    scene = _build(tmp_path)
    join = copy.deepcopy(scene.join)
    first, second = join["autostart"][:2]
    first["exec_guest_path"], second["exec_guest_path"] = (
        second["exec_guest_path"],
        first["exec_guest_path"],
    )

    report = identity.run(scene.directory, join)
    assert not report.ok
    assert any("per-file Exec mapping" in reason for reason in report.fails)


def test_linux_identity_reddens_when_two_desktop_files_trade_places(tmp_path):
    scene = _build(tmp_path)
    first_record, second_record = scene.join["autostart"][:2]
    first = Path(scene.directory) / first_record["served_relpath"]
    second = Path(scene.directory) / second_record["served_relpath"]
    first_data, second_data = first.read_bytes(), second.read_bytes()
    first.write_bytes(second_data)
    second.write_bytes(first_data)

    report = identity.run(scene.directory, scene.join)
    assert not report.ok
    assert any("per-file Exec mapping" in reason for reason in report.fails)


@pytest.mark.parametrize(
    ("field", "lie"),
    (
        ("name", "not-the-resident-name"),
        ("md5", "0" * 32),
        ("marker", "ARTIFACTFORGE-SYNTHETIC-0000000000000000"),
    ),
)
def test_linux_identity_rederives_every_declared_resident_identity_field(
    tmp_path, field, lie
):
    scene = _build(tmp_path)
    join = copy.deepcopy(scene.join)
    resident = next(record for record in join["residents"] if record["role"] == "subject")
    resident[field] = lie
    join["subject"][field] = lie  # Keep the redundant subject record internally consistent.

    report = identity.run(scene.directory, join)
    assert not report.ok
    assert any(field in reason for reason in report.fails)


def test_linux_identity_requires_the_single_declared_bash_history(tmp_path):
    scene = _build(tmp_path)
    source = Path(scene.directory) / scene.join["bash_history"]["served_relpath"]
    extra = source.parent / ".nested" / ".bash_history"
    extra.parent.mkdir()
    extra.write_bytes(source.read_bytes())

    report = identity.run(scene.directory, scene.join)
    assert not report.ok
    assert any("history served paths" in reason for reason in report.fails)


@pytest.mark.parametrize("mutation", ("entry", "writable-rx", "dynamic-tag", "exec-section"))
def test_independent_elf_safety_parser_rejects_structural_mutations(mutation):
    from artifactforge.content import build_elf

    data = bytearray(build_elf(b"mutation"))
    if mutation == "entry":
        struct.pack_into("<Q", data, 24, 0x1001)
    elif mutation == "writable-rx":
        # The fourth program header is the RX PT_LOAD; p_flags follows p_type.
        flags_offset = 64 + 3 * 56 + 4
        struct.pack_into("<I", data, flags_offset, 7)
    elif mutation == "dynamic-tag":
        struct.pack_into("<Q", data, 0x2000, 12)  # DT_INIT is outside the allowlist.
    else:
        section_offset = struct.unpack_from("<Q", data, 40)[0]
        interp_flags_offset = section_offset + 64 + 8
        flags = struct.unpack_from("<Q", data, interp_flags_offset)[0]
        struct.pack_into("<Q", data, interp_flags_offset, flags | 4)

    ok, detail = _elf_code_is_inert(bytes(data))
    assert not ok, detail


@pytest.mark.parametrize("offset", (700, 5000, 8334))
def test_independent_elf_safety_parser_rejects_nonzero_unclaimed_slack(offset):
    from artifactforge.content import build_elf

    data = bytearray(build_elf(b"slack-mutation"))
    assert data[offset] == 0
    data[offset] = 0xCC

    ok, detail = _elf_code_is_inert(bytes(data))
    assert not ok
    assert "non-zero unclaimed bytes" in detail


def test_independent_elf_safety_parser_rejects_virtual_load_overlap():
    from artifactforge.content import build_elf

    data = bytearray(build_elf(b"virtual-overlap-mutation"))
    # The third program header is the first (read-only) PT_LOAD. p_memsz is field six.
    first_load_memsz_offset = 64 + 2 * 56 + 40
    struct.pack_into("<Q", data, first_load_memsz_offset, 0x1001)

    ok, detail = _elf_code_is_inert(bytes(data))
    assert not ok
    assert "virtual-address PT_LOAD segments overlap" in detail


@pytest.mark.parametrize("size_delta", (-1, 1))
def test_independent_elf_safety_parser_rejects_noncanonical_file_size(size_delta):
    from artifactforge.content import build_elf

    canonical = build_elf(b"file-size-mutation")
    data = canonical[:size_delta] if size_delta < 0 else canonical + b"\x00"

    ok, detail = _elf_code_is_inert(data)
    assert not ok
    assert "file size" in detail
