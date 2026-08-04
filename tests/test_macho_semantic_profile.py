# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Typed Mach-O parser consensus and exact writer-profile regressions."""
from __future__ import annotations

import dataclasses
import struct

import pytest

from artifactforge.content.macho import build_macho
from artifactforge.content.seed import sub_seed
from artifactforge.gates import validity
from artifactforge.gates.oracles.macho_profile import (
    MachOProfileError,
    lief_macho_view,
    macholib_macho_view,
    validate_artifactforge_macho_profile,
)

lief = pytest.importorskip("lief")
pytest.importorskip("macholib")


def _write_macho(tmp_path, name: str, *, imports=None):
    path = tmp_path / name
    seed = sub_seed(b"artifactforge-macho-profile-tests", name)
    path.write_bytes(
        build_macho(
            seed,
            imports,
            sign_identifier=f"com.example.{name}",
        )
    )
    return path


def _views(path):
    return lief_macho_view(lief.parse(path)), macholib_macho_view(str(path))


def _command(data: bytes, wanted: int) -> int:
    count = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    for _ in range(count):
        command, size = struct.unpack_from("<II", data, offset)
        if command == wanted:
            return offset
        offset += size
    raise AssertionError(f"load command {wanted:#x} not found")


def test_lief_and_macholib_agree_on_every_typed_writer_dimension(tmp_path):
    configurations = set()
    for index in range(24):
        path = _write_macho(tmp_path, f"candidate-{index}")
        lief_view, macholib_view = _views(path)
        assert lief_view == macholib_view
        assert validate_artifactforge_macho_profile(lief_view).startswith(
            "profile=artifactforge-arm64-macho-v1"
        )
        configurations.add(tuple(dylib.name for dylib in lief_view.dylibs))

    # The loop must exercise optional-framework variation, not merely repeat one fixture.
    assert len(configurations) >= 4


def test_injected_parser_observation_disagreement_is_semantically_red(tmp_path):
    path = _write_macho(tmp_path, "disagreement")
    lief_view, macholib_view = _views(path)
    assert lief_view == macholib_view
    altered = dataclasses.replace(
        macholib_view,
        uuids=(bytes([macholib_view.uuids[0][0] ^ 1]) + macholib_view.uuids[0][1:],),
    )

    with pytest.raises(validity.SemanticError, match="type-exact Mach-O structure"):
        validity._validate_macho_consensus(
            str(path),
            {"lief": lief_view, "macholib": altered},
        )


_EXPLICIT_IMPORTS = [
    (
        "/usr/lib/libSystem.B.dylib",
        (1356, 0, 0),
        (1, 0, 0),
        ["_open", "_read", "_write"],
    ),
    (
        "/System/Library/Frameworks/Security.framework/Versions/A/Security",
        (61439, 0, 0),
        (1, 0, 0),
        ["_SecItemCopyMatching", "_SecCodeCopySigningInformation"],
    ),
]


def _mutate_stack_size(data: bytearray) -> None:
    main = _command(data, 0x80000028)  # LC_MAIN
    struct.pack_into("<Q", data, main + 16, 0x4000)


def _mutate_data_const_protection(data: bytearray) -> None:
    count = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    for _ in range(count):
        command, size = struct.unpack_from("<II", data, offset)
        if command == 0x19 and data[offset + 8:offset + 24].rstrip(b"\x00") == b"__DATA_CONST":
            struct.pack_into("<I", data, offset + 60, 1)
            return
        offset += size
    raise AssertionError("__DATA_CONST segment not found")


def _mutate_symbol_pool(data: bytearray) -> None:
    position = data.rfind(b"_open\x00")
    if position < 0:
        raise AssertionError("_open symbol not found")
    data[position:position + 6] = b"_noop\x00"


def _mutate_bind_symbol(data: bytearray) -> None:
    dyld_info = _command(data, 0x80000022)  # LC_DYLD_INFO_ONLY
    bind_offset, bind_size = struct.unpack_from("<II", data, dyld_info + 16)
    position = data.index(b"_write\x00", bind_offset, bind_offset + bind_size)
    data[position:position + 6] = b"_wr1te"


def _mutate_to_equivalent_noncanonical_bind_opcode(data: bytearray) -> None:
    dyld_info = _command(data, 0x80000022)  # LC_DYLD_INFO_ONLY
    bind_offset, bind_size = struct.unpack_from("<II", data, dyld_info + 16)
    stream = bytes(data[bind_offset:bind_offset + bind_size])
    assert stream[:4] == b"\x51\x72\x00\x11"
    assert stream[-2:] == b"\x00\x00"
    # Encode ordinal 1 as SET_DYLIB_ORDINAL_ULEB instead of the writer's immediate form.
    replacement = stream[:3] + b"\x20\x01" + stream[4:-1]
    assert len(replacement) == bind_size
    data[bind_offset:bind_offset + bind_size] = replacement


def _mutate_indirect_symbol_index(data: bytearray) -> None:
    dysymtab = _command(data, 0x0B)  # LC_DYSYMTAB
    indirect_offset = struct.unpack_from("<I", data, dysymtab + 56)[0]
    assert struct.unpack_from("<I", data, indirect_offset)[0] == 2
    struct.pack_into("<I", data, indirect_offset, 3)


def _mutate_got_entry(data: bytearray) -> None:
    count = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    for _ in range(count):
        command, size = struct.unpack_from("<II", data, offset)
        if command == 0x19 and data[offset + 8:offset + 24].rstrip(b"\x00") == b"__DATA_CONST":
            section = offset + 72
            assert data[section:section + 16].rstrip(b"\x00") == b"__got"
            got_offset = struct.unpack_from("<I", data, section + 48)[0]
            assert struct.unpack_from("<Q", data, got_offset)[0] == 0
            struct.pack_into("<Q", data, got_offset, 1)
            return
        offset += size
    raise AssertionError("__DATA_CONST,__got not found")


@pytest.mark.parametrize(
    ("mutate", "message"),
    (
        (_mutate_stack_size, "LC_MAIN"),
        (_mutate_data_const_protection, "__DATA_CONST"),
        (_mutate_symbol_pool, "undefined symbols"),
    ),
    ids=("main-stack", "segment-protection", "symbol-pool"),
)
def test_parser_valid_mutations_violate_the_exact_profile(tmp_path, mutate, message):
    path = _write_macho(tmp_path, "mutated", imports=_EXPLICIT_IMPORTS)
    data = bytearray(path.read_bytes())
    mutate(data)
    path.write_bytes(data)

    lief_view, macholib_view = _views(path)
    assert lief_view == macholib_view, "container readers must still agree after the mutation"
    with pytest.raises(MachOProfileError, match=message):
        validate_artifactforge_macho_profile(lief_view)


@pytest.mark.parametrize(
    ("mutate", "message"),
    (
        (_mutate_bind_symbol, "dyld bindings"),
        (_mutate_to_equivalent_noncanonical_bind_opcode, "bind opcodes"),
        (_mutate_indirect_symbol_index, "indirect-symbol indexes"),
        (_mutate_got_entry, "GOT entries"),
    ),
    ids=("bind-symbol", "equivalent-bind-opcode", "indirect-symbol-index", "got-entry"),
)
def test_linkage_table_mutations_are_consensus_green_but_profile_red(
    tmp_path, mutate, message
):
    path = _write_macho(tmp_path, "linkage-mutated", imports=_EXPLICIT_IMPORTS)
    before = validity.run(str(tmp_path))
    assert before.ok, before.render()
    data = bytearray(path.read_bytes())
    mutate(data)
    path.write_bytes(data)

    lief_view, macholib_view = _views(path)
    assert lief_view == macholib_view, "both extraction implementations must observe the edit"
    with pytest.raises(MachOProfileError, match=message):
        validate_artifactforge_macho_profile(lief_view)

    after = validity.run(str(tmp_path))
    assert after.metrics["oracle_reads_passed"] == after.metrics["oracle_reads_total"] == 2
    assert after.metrics["claim_scopes"]["independent_consensus"] == {
        "passed": 1,
        "total": 1,
    }
    assert after.metrics["claim_scopes"]["declared_profile_conformance"] == {
        "passed": 0,
        "total": 1,
    }
    new = [failure for failure in after.fails if failure not in before.fails]
    assert any("artifactforge-arm64-macho-v1-profile" in failure for failure in new), new
    assert not any("macho-consensus" in failure for failure in new), new


def test_gate_records_consensus_and_profile_as_separate_scopes(tmp_path):
    _write_macho(tmp_path, "only-artifact")
    report = validity.run(str(tmp_path))
    assert report.ok, report.render()
    assert report.metrics["oracle_reads_passed"] == 2
    assert report.metrics["oracle_reads_total"] == 2
    assert report.metrics["semantic_checks_passed"] == 2
    assert report.metrics["semantic_checks_total"] == 2
    assert report.metrics["claim_scopes"] == {
        "container_acceptance": {"passed": 2, "total": 2},
        "semantic_extraction": {"passed": 2, "total": 2},
        "independent_consensus": {"passed": 1, "total": 1},
        "declared_profile_conformance": {"passed": 1, "total": 1},
        "downstream_consumer_compatibility": {"passed": 0, "total": 0},
    }
