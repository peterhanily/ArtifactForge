# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The Linux content writer emits a real, inert, deterministic ELF64 PIE."""
from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import sys

import pytest

from artifactforge.content import ContentStore
from artifactforge.content.elf import (
    DF_1_PIE,
    DT_FLAGS_1,
    DT_NEEDED,
    DT_NULL,
    DT_STRSZ,
    DT_STRTAB,
    ELF_ENTRY_CODE,
    ELF_INTERPRETER,
    ELF_NEEDED,
    ELF_NOTE_NAME,
    ELF_NOTE_TYPE,
    PF_R,
    PF_W,
    PF_X,
    PT_DYNAMIC,
    PT_GNU_RELRO,
    PT_GNU_STACK,
    PT_INTERP,
    PT_LOAD,
    PT_NOTE,
    build_elf,
)
from artifactforge.content.seed import sub_seed

_ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
_PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
_SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")


def _store(tmp_path):
    return ContentStore("artifactforge::elf-test", str(tmp_path / "content"))


def _header(data: bytes) -> dict[str, int | bytes]:
    fields = _ELF_HEADER.unpack_from(data)
    keys = (
        "ident",
        "type",
        "machine",
        "version",
        "entry",
        "phoff",
        "shoff",
        "flags",
        "ehsize",
        "phentsize",
        "phnum",
        "shentsize",
        "shnum",
        "shstrndx",
    )
    return dict(zip(keys, fields, strict=True))


def _program_headers(data: bytes) -> list[dict[str, int]]:
    header = _header(data)
    keys = ("type", "flags", "offset", "vaddr", "paddr", "filesz", "memsz", "align")
    return [
        dict(
            zip(
                keys,
                _PROGRAM_HEADER.unpack_from(
                    data, int(header["phoff"]) + index * int(header["phentsize"])
                ),
                strict=True,
            )
        )
        for index in range(int(header["phnum"]))
    ]


def _sections(data: bytes) -> dict[str, dict[str, int]]:
    header = _header(data)
    keys = ("name", "type", "flags", "addr", "offset", "size", "link", "info", "align", "entsize")
    entries = [
        dict(
            zip(
                keys,
                _SECTION_HEADER.unpack_from(
                    data, int(header["shoff"]) + index * int(header["shentsize"])
                ),
                strict=True,
            )
        )
        for index in range(int(header["shnum"]))
    ]
    names = entries[int(header["shstrndx"])]
    strings = data[names["offset"] : names["offset"] + names["size"]]

    def read_name(offset: int) -> str:
        end = strings.index(b"\x00", offset)
        return strings[offset:end].decode("ascii")

    return {read_name(entry["name"]): entry for entry in entries}


def _segment_bytes(data: bytes, segment: dict[str, int]) -> bytes:
    return data[segment["offset"] : segment["offset"] + segment["filesz"]]


def test_golden_bytes_and_hashlib_identities(tmp_path):
    seed = sub_seed(b"scenario", "elf:standalone")
    data = build_elf(seed)
    assert len(data) == 8784
    assert hashlib.sha256(data).hexdigest() == (
        "8be08b14cd78a877fad538e246e39dc2170458f49d984bd2b3b42b415374e965"
    )

    content = _store(tmp_path).materialize("elf:tool")
    assert content.fmt == "elf"
    assert content.sha256 == hashlib.sha256(content.bytes).hexdigest()
    assert content.sha1 == hashlib.sha1(content.bytes).hexdigest()
    assert content.md5 == hashlib.md5(content.bytes).hexdigest()  # noqa: S324
    assert content.imphash == content.symhash == content.cdhash == ""
    with open(content.path, "rb") as materialized:
        assert materialized.read() == content.bytes


def test_store_and_writer_are_deterministic_and_seed_sensitive(tmp_path):
    first = _store(tmp_path / "a").materialize("elf:tool")
    again = _store(tmp_path / "b").materialize("elf:tool")
    other = _store(tmp_path / "c").materialize("elf:other")
    assert first.bytes == again.bytes
    assert first.sha256 == again.sha256
    assert first.bytes != other.bytes
    assert first.sha256 != other.sha256
    assert first.marker != other.marker


def test_header_program_segments_and_entry_are_exactly_bounded(tmp_path):
    content = _store(tmp_path).materialize("elf:tool")
    data = content.bytes
    header = _header(data)
    assert bytes(header["ident"]) == b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    assert (header["type"], header["machine"], header["version"]) == (3, 62, 1)
    assert header["ehsize"] == _ELF_HEADER.size
    assert header["phentsize"] == _PROGRAM_HEADER.size
    assert header["shentsize"] == _SECTION_HEADER.size

    segments = _program_headers(data)
    for segment in segments:
        assert segment["filesz"] <= segment["memsz"]
        assert segment["offset"] + segment["filesz"] <= len(data)

    loads = [segment for segment in segments if segment["type"] == PT_LOAD]
    assert [segment["flags"] for segment in loads] == [PF_R, PF_R | PF_X, PF_R | PF_W]
    assert len(loads) == 3
    for segment in loads:
        assert segment["offset"] % segment["align"] == segment["vaddr"] % segment["align"]

    for left, right in zip(loads, loads[1:]):
        assert left["offset"] + left["filesz"] <= right["offset"]
        assert left["vaddr"] + left["memsz"] <= right["vaddr"]

    executable = [segment for segment in loads if segment["flags"] & PF_X]
    assert len(executable) == 1
    execute = executable[0]
    assert execute["filesz"] == execute["memsz"] == len(ELF_ENTRY_CODE) == 9
    entry_offset = header["entry"] - execute["vaddr"] + execute["offset"]
    assert entry_offset == execute["offset"]
    assert _segment_bytes(data, execute) == ELF_ENTRY_CODE
    assert data[entry_offset : entry_offset + 9] == bytes.fromhex("31ffb83c0000000f05")
    assert data.count(ELF_ENTRY_CODE) == 1

    stacks = [segment for segment in segments if segment["type"] == PT_GNU_STACK]
    assert len(stacks) == 1
    assert stacks[0]["flags"] == PF_R | PF_W
    assert not (stacks[0]["flags"] & PF_X)


def test_sections_are_bounded_and_expose_no_second_execution_surface(tmp_path):
    data = _store(tmp_path).materialize("elf:tool").bytes
    header = _header(data)
    assert header["shoff"] + header["shnum"] * header["shentsize"] == len(data)
    sections = _sections(data)
    assert set(sections) == {
        "",
        ".interp",
        ".note.artifactforge",
        ".dynstr",
        ".text",
        ".dynamic",
        ".shstrtab",
    }
    for section in sections.values():
        assert section["offset"] + section["size"] <= len(data)

    executable = [name for name, section in sections.items() if section["flags"] & 0x4]
    assert executable == [".text"]
    text = sections[".text"]
    assert data[text["offset"] : text["offset"] + text["size"]] == ELF_ENTRY_CODE

    forbidden = {
        ".dynsym",
        ".symtab",
        ".init",
        ".fini",
        ".init_array",
        ".fini_array",
        ".preinit_array",
        ".plt",
        ".got",
        ".got.plt",
        ".rela.dyn",
        ".rela.plt",
        ".tdata",
        ".tbss",
    }
    assert forbidden.isdisjoint(sections)
    # SHT_DYNSYM, INIT_ARRAY, FINI_ARRAY, and PREINIT_ARRAY are absent by type too.
    assert {section["type"] for section in sections.values()}.isdisjoint({11, 14, 15, 16})


def test_interpreter_dynamic_allowlist_relro_and_note_marker(tmp_path):
    content = _store(tmp_path).materialize("elf:tool")
    data = content.bytes
    segments = _program_headers(data)
    sections = _sections(data)

    interpreter = [segment for segment in segments if segment["type"] == PT_INTERP]
    assert len(interpreter) == 1
    assert _segment_bytes(data, interpreter[0]) == ELF_INTERPRETER

    dynamic_segment = [segment for segment in segments if segment["type"] == PT_DYNAMIC]
    relro = [segment for segment in segments if segment["type"] == PT_GNU_RELRO]
    assert len(dynamic_segment) == len(relro) == 1
    dynamic_segment = dynamic_segment[0]
    assert (dynamic_segment["offset"], dynamic_segment["filesz"]) == (
        sections[".dynamic"]["offset"],
        sections[".dynamic"]["size"],
    )
    assert (relro[0]["offset"], relro[0]["filesz"]) == (
        dynamic_segment["offset"],
        dynamic_segment["filesz"],
    )

    entries = [
        struct.unpack_from("<QQ", data, dynamic_segment["offset"] + offset)
        for offset in range(0, dynamic_segment["filesz"], 16)
    ]
    assert entries == [
        (DT_NEEDED, 1),
        (DT_STRTAB, sections[".dynstr"]["addr"]),
        (DT_STRSZ, sections[".dynstr"]["size"]),
        (DT_FLAGS_1, DF_1_PIE),
        (DT_NULL, 0),
    ]
    dynstr = data[
        sections[".dynstr"]["offset"] :
        sections[".dynstr"]["offset"] + sections[".dynstr"]["size"]
    ]
    assert dynstr == b"\x00" + ELF_NEEDED + b"\x00"

    notes = [segment for segment in segments if segment["type"] == PT_NOTE]
    assert len(notes) == 1
    note = _segment_bytes(data, notes[0])
    assert (notes[0]["offset"], notes[0]["filesz"]) == (
        sections[".note.artifactforge"]["offset"],
        sections[".note.artifactforge"]["size"],
    )
    name_size, description_size, note_type = struct.unpack_from("<III", note)
    name_start = 12
    description_start = name_start + ((name_size + 3) & ~3)
    assert note_type == ELF_NOTE_TYPE
    assert note[name_start : name_start + name_size] == ELF_NOTE_NAME
    assert note[description_start : description_start + description_size] == content.marker.encode()
    assert data.count(content.marker.encode()) == 1


def test_lief_and_pyelftools_independently_agree(tmp_path):
    lief = pytest.importorskip("lief")
    elftools = pytest.importorskip("elftools.elf.elffile")
    content = _store(tmp_path).materialize("elf:tool")

    lief_binary = lief.parse(content.path)
    assert lief_binary is not None
    assert str(lief_binary.header.file_type).endswith("DYN")
    assert str(lief_binary.header.machine_type).endswith("X86_64")
    assert lief_binary.interpreter == ELF_INTERPRETER[:-1].decode()
    assert list(lief_binary.libraries) == [ELF_NEEDED.decode()]
    assert list(lief_binary.imported_symbols) == []

    with open(content.path, "rb") as stream:
        elf = elftools.ELFFile(stream)
        assert elf.header["e_type"] == "ET_DYN"
        assert elf.header["e_machine"] == "EM_X86_64"
        assert elf.header["e_entry"] == lief_binary.entrypoint
        assert elf.get_section_by_name(".dynsym") is None
        assert elf.get_section_by_name(".text").data() == ELF_ENTRY_CODE

        interpreter = next(segment for segment in elf.iter_segments()
                           if segment.header.p_type == "PT_INTERP")
        assert interpreter.data() == ELF_INTERPRETER
        dynamic = next(segment for segment in elf.iter_segments()
                       if segment.header.p_type == "PT_DYNAMIC")
        tags = list(dynamic.iter_tags())
        needed = [tag.needed for tag in tags if tag.entry.d_tag == "DT_NEEDED"]
        assert needed == list(lief_binary.libraries) == [ELF_NEEDED.decode()]
        assert [tag.entry.d_tag for tag in tags] == [
            "DT_NEEDED",
            "DT_STRTAB",
            "DT_STRSZ",
            "DT_FLAGS_1",
            "DT_NULL",
        ]


def test_no_wall_clock_hash_seed_timezone_or_locale_leaks_into_elf(tmp_path):
    code = (
        "import tempfile;"
        "from artifactforge.content import ContentStore;"
        "print(ContentStore('artifactforge::elf-test', tempfile.mkdtemp())"
        ".materialize('elf:tool').sha256)"
    )
    outputs = []
    for seed, timezone, locale in (
        ("0", "UTC", "C"),
        ("7", "Asia/Tokyo", "C"),
        ("31337", "America/New_York", "C"),
    ):
        environment = dict(
            os.environ,
            PYTHONHASHSEED=seed,
            TZ=timezone,
            LC_ALL=locale,
            SOURCE_DATE_EPOCH=str(1_700_000_000 + int(seed)),
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            env=environment,
            check=True,
        )
        outputs.append(result.stdout.strip())
    assert len(set(outputs)) == 1, outputs
