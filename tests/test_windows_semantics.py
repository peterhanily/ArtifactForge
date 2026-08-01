# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Windows validity semantics, including parseable mutations that must turn Gate 1 red."""
from __future__ import annotations

import os
import struct

import pytest

from artifactforge.artifacts.prefetch import build_prefetch, prefetch_name_hash
from artifactforge.content import ContentStore
from artifactforge.gates import validity

pefile = pytest.importorskip("pefile")
lief = pytest.importorskip("lief")
windowsprefetch = pytest.importorskip("windowsprefetch")
pyscca = pytest.importorskip("pyscca")

XP_NOTEPAD_PATH = "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\NOTEPAD.EXE"
XP_NOTEPAD_HASH = 0x189578DA
XP_NOTEPAD_CONV_KEY = 0x0068988D


def _new_fails(before, after):
    return [failure for failure in after.fails if failure not in before.fails]


def _write(path, data: bytes) -> str:
    path.write_bytes(data)
    return str(path)


def _conv_key(path: str) -> int:
    value = 0
    for byte in path.upper().encode("utf-16-le"):
        value = (37 * value + byte) & 0xFFFFFFFF
    return value


def test_scca_xp_known_answer_distinguishes_convkey_from_final_hash():
    """A real XP vector proves the multiply-by-37 intermediate is not the PF hash."""
    assert _conv_key(XP_NOTEPAD_PATH) == XP_NOTEPAD_CONV_KEY
    assert XP_NOTEPAD_CONV_KEY != XP_NOTEPAD_HASH
    assert prefetch_name_hash(XP_NOTEPAD_PATH) == XP_NOTEPAD_HASH
    assert validity._independent_scca_xp_hash(XP_NOTEPAD_PATH) == XP_NOTEPAD_HASH


def test_prefetch_semantics_bind_path_header_and_filename(tmp_path):
    name = f"NOTEPAD.EXE-{XP_NOTEPAD_HASH:08X}.pf"
    _write(tmp_path / name, build_prefetch("notepad.exe", XP_NOTEPAD_PATH, 3))

    report = validity.run(str(tmp_path))
    assert report.ok, report.render()
    assert report.metrics["oracle_reads_passed"] == 2
    assert report.metrics["semantic_checks_passed"] == 1


def test_prefetch_hash_mutation_stays_parseable_but_fails_semantics(tmp_path):
    """MUTATION: change only the embedded path hash; both format readers still open it."""
    name = f"NOTEPAD.EXE-{XP_NOTEPAD_HASH:08X}.pf"
    path = tmp_path / name
    data = bytearray(build_prefetch("notepad.exe", XP_NOTEPAD_PATH, 3))
    _write(path, data)
    before = validity.run(str(tmp_path))
    assert before.ok, before.render()

    embedded_hash = struct.unpack_from("<I", data, 76)[0]
    struct.pack_into("<I", data, 76, embedded_hash ^ 1)
    _write(path, data)

    assert windowsprefetch.Prefetch(str(path)).executableName == "NOTEPAD.EXE"
    parser = pyscca.file()
    parser.open(str(path))
    try:
        assert parser.get_executable_filename() == "NOTEPAD.EXE"
    finally:
        parser.close()

    new = _new_fails(before, validity.run(str(tmp_path)))
    assert any("scca-v17-path-hash" in failure for failure in new), new


def _pe_path(tmp_path) -> str:
    content = ContentStore("artifactforge::windows-semantics", str(tmp_path / "cache")).materialize(
        "pe:subject"
    )
    scene = tmp_path / "scene"
    scene.mkdir()
    return _write(scene / "subject.exe", content.bytes)


def test_pefile_and_lief_independently_agree_on_imports_and_imphash(tmp_path):
    path = _pe_path(tmp_path)
    report = validity.run(os.path.dirname(path))
    assert report.ok, report.render()
    assert report.metrics["oracle_reads_passed"] == 2
    assert report.metrics["semantic_checks_passed"] == 1

    pefile_result = validity._read_pefile(path)
    lief_result = validity._read_lief(path)
    assert pefile_result.imports == lief_result.imports
    assert pefile_result.imphash == lief_result.imphash
    assert sum(len(names) for _dll, names in pefile_result.imports) >= 2


def test_missing_import_directory_stays_parseable_but_fails_semantics(tmp_path):
    """MUTATION: clear the import directory while preserving a parseable PE container."""
    path = _pe_path(tmp_path)
    before = validity.run(os.path.dirname(path))
    assert before.ok, before.render()

    parsed = pefile.PE(path)
    import_directory_offset = parsed.OPTIONAL_HEADER.DATA_DIRECTORY[1].get_file_offset()
    with open(path, "r+b") as file:
        file.seek(import_directory_offset)
        file.write(b"\x00" * 8)

    assert pefile.PE(path).NT_HEADERS.Signature == 0x4550
    assert lief.parse(path) is not None

    new = _new_fails(before, validity.run(os.path.dirname(path)))
    assert any("no named imports" in failure for failure in new), new
    assert any("import-consensus" in failure for failure in new), new
