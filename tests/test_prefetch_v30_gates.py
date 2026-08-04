# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Gate 1/2/3 integration and mutation coverage for compressed Prefetch v30."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
import shutil
import struct

import pytest

from artifactforge import suite
from artifactforge.artifacts.xpress_huffman import compress_xpress_huffman
from artifactforge.compose.scene import build_windows_scene
from artifactforge.content import ContentStore
from artifactforge.gates import identity, inertness, validity
from artifactforge.gates.oracles.prefetch_profile import (
    MAM_XPRESS_HUFFMAN_MAGIC,
    decode_mam_xpress_huffman,
    parse_mam_prefetch_v30_variant1,
)
from artifactforge.model import windows_profile


KEY = suite.scenario_key(suite.PUBLIC_DEV_KEY, "test-prefetch-v30-gates")


@pytest.fixture(scope="module")
def windows_scene(tmp_path_factory: pytest.TempPathFactory):
    root = tmp_path_factory.mktemp("prefetch-v30-gates")
    store = ContentStore("artifactforge::prefetch-v30-gates", str(root / "content"))
    return build_windows_scene(
        store,
        skey=KEY,
        profile=windows_profile(),
        scene_dir=str(root / "scene"),
        staging_dir=str(root / "staging"),
    )


def _copy_scene(scene, tmp_path: Path, label: str) -> Path:
    destination = tmp_path / label
    shutil.copytree(scene.directory, destination)
    return destination


def _persisted_prefetch(scene_dir: Path, join: dict) -> Path:
    expected = join["persisted"]["name"].casefold()
    matches = [
        path
        for path in scene_dir.glob("*.pf")
        if parse_mam_prefetch_v30_variant1(path.read_bytes()).executable_name.casefold() == expected
    ]
    assert len(matches) == 1
    return matches[0]


def _isolated_prefetch(scene, tmp_path: Path) -> tuple[Path, Path]:
    directory = tmp_path / "single-prefetch"
    directory.mkdir()
    source = _persisted_prefetch(Path(scene.directory), scene.join)
    target = directory / source.name
    shutil.copy2(source, target)
    return directory, target


def _rewrite_inner(path: Path, mutation: Callable[[bytearray], None]) -> None:
    inner = bytearray(decode_mam_xpress_huffman(path.read_bytes()))
    mutation(inner)
    encoded = compress_xpress_huffman(bytes(inner))
    path.write_bytes(MAM_XPRESS_HUFFMAN_MAGIC + struct.pack("<I", len(inner)) + encoded)


def test_generated_windows_scene_is_green_across_gates(windows_scene) -> None:
    reports = (
        validity.run(windows_scene.directory),
        identity.run(windows_scene.directory, windows_scene.join),
        inertness.run(windows_scene.directory),
    )

    for report in reports:
        assert report.ok, report.render()
    assert reports[0].metrics["oracle_reads_passed"] == reports[0].metrics["oracle_reads_total"]
    assert (
        reports[0].metrics["semantic_checks_passed"] == reports[0].metrics["semantic_checks_total"]
    )
    assert reports[1].metrics["checks_joined"] == reports[1].metrics["checks_total"]
    assert reports[2].metrics["formats_marked"] == reports[2].metrics["formats_total"]


def test_missing_nonpivot_prefetch_reddens_exact_set_checks(windows_scene, tmp_path: Path) -> None:
    directory = _copy_scene(windows_scene, tmp_path, "missing-nonpivot-prefetch")
    protected = {
        windows_scene.join["persisted"]["name"].casefold(),
        windows_scene.join["orphan_execution"].casefold(),
    }
    victim = next(
        path
        for path in sorted(directory.glob("*.pf"))
        if parse_mam_prefetch_v30_variant1(path.read_bytes()).executable_name.casefold()
        not in protected
    )
    missing_name = parse_mam_prefetch_v30_variant1(victim.read_bytes()).executable_name.casefold()
    assert missing_name in {
        name.casefold() for name in windows_scene.join["prefetch"]["execution_names"]
    }
    victim.unlink()

    report = identity.run(str(directory), windows_scene.join)

    assert not report.ok
    assert any("exact Prefetch artifact count" in failure for failure in report.fails)
    assert any("exact execution names" in failure for failure in report.fails)


def test_dissect_counts_as_semantic_extraction_not_container_acceptance(
    windows_scene, tmp_path: Path
) -> None:
    directory, _path = _isolated_prefetch(windows_scene, tmp_path)

    report = validity.run(str(directory))

    assert report.ok, report.render()
    assert report.metrics["claim_scopes"] == {
        "container_acceptance": {"passed": 2, "total": 2},
        "semantic_extraction": {"passed": 3, "total": 3},
        "independent_consensus": {"passed": 1, "total": 1},
        "declared_profile_conformance": {"passed": 1, "total": 1},
        "downstream_consumer_compatibility": {"passed": 0, "total": 0},
    }


def test_mam_algorithm_mutation_reddens_all_three_gates(windows_scene, tmp_path: Path) -> None:
    directory = _copy_scene(windows_scene, tmp_path, "bad-algorithm")
    path = _persisted_prefetch(directory, windows_scene.join)
    data = bytearray(path.read_bytes())
    data[3] = 3
    path.write_bytes(data)

    gate1 = validity.run(str(directory))
    gate2 = identity.run(str(directory), windows_scene.join)
    gate3 = inertness.run(str(directory))

    assert not gate1.ok and any("not MAM algorithm 4" in failure for failure in gate1.fails)
    assert not gate2.ok and any(
        "outside the bounded v30 profile" in failure for failure in gate2.fails
    )
    assert not gate3.ok and any(
        "cannot expose a bounded logical marker" in failure for failure in gate3.fails
    )


def test_oversized_declared_output_is_rejected_before_external_parser_invocation(
    windows_scene, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory, path = _isolated_prefetch(windows_scene, tmp_path)
    data = bytearray(path.read_bytes())
    struct.pack_into("<I", data, 4, 4097)
    path.write_bytes(data)

    import pyscca
    from dissect.target.plugins.os.windows import prefetch as dissect_prefetch

    external_calls: list[str] = []

    def unexpected_external_call(*_args, **_kwargs):
        external_calls.append("called")
        raise AssertionError("oversized MAM reached an external parser")

    monkeypatch.setattr(pyscca, "file", unexpected_external_call)
    monkeypatch.setattr(dissect_prefetch, "Prefetch", unexpected_external_call)

    report = validity.run(str(directory))

    assert not report.ok
    assert external_calls == []
    assert sum("declared output size is outside" in failure for failure in report.fails) == 3
    assert report.metrics["claim_scopes"]["container_acceptance"] == {
        "passed": 0,
        "total": 2,
    }
    assert report.metrics["claim_scopes"]["semantic_extraction"] == {
        "passed": 0,
        "total": 3,
    }


def test_canonical_tail_mutation_is_owned_by_profile_conformance(
    windows_scene, tmp_path: Path
) -> None:
    directory = _copy_scene(windows_scene, tmp_path, "lowercase-tail")
    path = _persisted_prefetch(directory, windows_scene.join)
    original = parse_mam_prefetch_v30_variant1(path.read_bytes())

    def lowercase_first_tail_character(inner: bytearray) -> None:
        encoded_path = original.metric_filenames[0].encode("utf-16-le")
        start = inner.find(encoded_path)
        character = start + (len(original.volume_device_path) + 1) * 2
        assert start >= 0 and 65 <= inner[character] <= 90 and inner[character + 1] == 0
        inner[character] += 32

    _rewrite_inner(path, lowercase_first_tail_character)
    assert (
        parse_mam_prefetch_v30_variant1(path.read_bytes()).metric_filenames[0]
        != (original.metric_filenames[0])
    )

    gate1 = validity.run(str(directory))
    gate2 = identity.run(str(directory), windows_scene.join)
    gate3 = inertness.run(str(directory))

    assert not gate1.ok
    assert gate1.metrics["oracle_reads_passed"] == gate1.metrics["oracle_reads_total"]
    assert (
        gate1.metrics["claim_scopes"]["independent_consensus"]["passed"]
        == gate1.metrics["claim_scopes"]["independent_consensus"]["total"]
    )
    assert any(
        "executable-path tail is not canonical uppercase" in failure for failure in gate1.fails
    )
    assert gate2.ok, gate2.render()
    assert gate3.ok, gate3.render()


def test_reserved_inner_byte_is_rejected_by_raw_reader_and_identity(
    windows_scene, tmp_path: Path
) -> None:
    directory = _copy_scene(windows_scene, tmp_path, "reserved-inner")
    path = _persisted_prefetch(directory, windows_scene.join)

    def set_reserved_byte(inner: bytearray) -> None:
        assert inner[120] == 0
        inner[120] = 1

    _rewrite_inner(path, set_reserved_byte)
    gate1 = validity.run(str(directory))
    gate2 = identity.run(str(directory), windows_scene.join)
    gate3 = inertness.run(str(directory))

    assert not gate1.ok
    assert gate1.metrics["oracle_reads_passed"] == gate1.metrics["oracle_reads_total"] - 1
    assert (
        gate1.metrics["claim_scopes"]["independent_consensus"]["passed"]
        == gate1.metrics["claim_scopes"]["independent_consensus"]["total"]
    )
    assert any(
        "prefetch-raw rejected" in failure and "reserved bytes" in failure
        for failure in gate1.fails
    )
    assert not gate2.ok and any("reserved bytes" in failure for failure in gate2.fails)
    assert gate3.ok, gate3.render()


def test_on_disk_prefetch_name_must_bind_header_hash(windows_scene, tmp_path: Path) -> None:
    directory = _copy_scene(windows_scene, tmp_path, "wrong-pf-name")
    path = _persisted_prefetch(directory, windows_scene.join)
    replacement = "0" if path.stem[-1] != "0" else "1"
    renamed = path.with_name(path.stem[:-1] + replacement + path.suffix)
    path.rename(renamed)

    gate1 = validity.run(str(directory))

    assert not gate1.ok
    assert gate1.metrics["oracle_reads_passed"] == gate1.metrics["oracle_reads_total"]
    assert any("prefetch filename" in failure and "!=" in failure for failure in gate1.fails)


def test_decoded_marker_mutation_reddens_profile_and_inertness(
    windows_scene, tmp_path: Path
) -> None:
    directory = _copy_scene(windows_scene, tmp_path, "missing-decoded-marker")
    path = _persisted_prefetch(directory, windows_scene.join)

    def corrupt_marker(inner: bytearray) -> None:
        marker = "ARTIFACTFORGE".encode("utf-16-le")
        offset = inner.find(marker)
        assert offset >= 0
        inner[offset] = ord("X")

    _rewrite_inner(path, corrupt_marker)
    decoded = decode_mam_xpress_huffman(path.read_bytes())
    assert b"ARTIFACTFORGE" not in decoded
    assert "ARTIFACTFORGE".encode("utf-16-le") not in decoded

    gate1 = validity.run(str(directory))
    gate2 = identity.run(str(directory), windows_scene.join)
    gate3 = inertness.run(str(directory))

    assert not gate1.ok and any("filename strings" in failure for failure in gate1.fails)
    assert gate1.metrics["oracle_reads_passed"] == gate1.metrics["oracle_reads_total"]
    assert gate2.ok, gate2.render()
    assert not gate3.ok and any(
        "carries no in-band synthetic marker" in failure for failure in gate3.fails
    )
