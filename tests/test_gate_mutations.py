# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The mutation register — the sixth binding, and the one that makes the rest mean anything.

Every gate ships with a named mutation that must turn it red. A gate never observed to fail
proves nothing, and this repository has the receipts: `tests/test_real_run_join.py` asserted
`amcache == "0000" + c.sha1` one line after assigning exactly that, and stayed green when the
hash it was supposedly checking was replaced with the string GARBAGE-NOT-A-SHA1.

Each test compares the gate's failures before and after the mutation and requires a NEW
failure naming the thing that was broken. Comparing before and after, rather than simply
asserting redness, matters because some gates are legitimately red already — a test that only
checked redness would pass without the mutation doing anything at all.
"""
import dataclasses
import hashlib
import os
import struct

import pytest

from artifactforge import suite
from artifactforge.artifacts.hive import build_amcache_hive
from artifactforge.bench.benchmark import generate_suite
from artifactforge.gates import identity, inertness, solvability, validity

pytest.importorskip("pefile")
pytest.importorskip("regipy")
pytest.importorskip("windowsprefetch")

HOLDOUT_KEY = bytes.fromhex("a3" * 32)


def _new_fails(before, after):
    return [f for f in after.fails if f not in before.fails]


def _suite(tmp_path, name="s", n=2, key=None):
    return generate_suite(n, str(tmp_path / name), key=key or suite.PUBLIC_DEV_KEY,
                          kind="dev" if key is None else "holdout")


def _windows(tmp_path, name="s"):
    return next(t for t in _suite(tmp_path, name) if t.family == "windows")


def _persisted_pe(task):
    return os.path.join(task.directory, task.join["persisted"]["name"])


# --- Gate 1: corrupt an artifact and its parser must refuse it ------------------------

def test_validity_reddens_when_an_artifact_is_corrupted(tmp_path):
    """MUTATION: truncate Amcache.hve to 200 bytes. regipy must reject it."""
    task = _windows(tmp_path)
    before = validity.run(task.directory)

    with open(os.path.join(task.directory, "Amcache.hve"), "r+b") as f:
        f.truncate(200)

    new = _new_fails(before, validity.run(task.directory))
    assert any("regipy rejected" in f for f in new), f"new fails: {new}"


# --- Gate 2: break a pivot and the identity gate must notice --------------------------

def test_identity_reddens_when_the_pe_no_longer_matches_the_scene(tmp_path):
    """MUTATION: append one byte to the persisted binary. Every digest is now wrong."""
    task = _windows(tmp_path)
    before = identity.run(task.directory, task.join)
    assert before.ok, f"gate 2 must be green before the mutation:\n{before.render()}"

    with open(_persisted_pe(task), "ab") as f:
        f.write(b"\x00")

    after = identity.run(task.directory, task.join)
    assert not after.ok
    assert any("sha256" in f for f in _new_fails(before, after))


def test_identity_reddens_when_the_amcache_hash_join_is_destroyed(tmp_path):
    """MUTATION: rewrite every Amcache FileId so none matches a resident file.

    This is exactly the failure the predecessor test could not see: the registry still
    parses, the scene's own record is untouched, and only the cross-artifact claim is false.
    """
    task = _windows(tmp_path)
    before = identity.run(task.directory, task.join)
    assert before.ok

    rows = [(hashlib.sha1(f"nothing-here-{i}".encode()).hexdigest(),   # noqa: S324
             f"c:\\gone\\p{i}.exe", f"p{i}.exe", 4096) for i in range(8)]
    with open(os.path.join(task.directory, "Amcache.hve"), "wb") as f:
        f.write(build_amcache_hive(rows))

    after = identity.run(task.directory, task.join)
    assert not after.ok
    assert any("recorded hash belongs to a resident file" in f
               for f in _new_fails(before, after)), _new_fails(before, after)


def test_identity_reddens_when_persistence_points_somewhere_else(tmp_path):
    """MUTATION: delete the persisted binary. The autostart now names nothing present."""
    task = _windows(tmp_path)
    before = identity.run(task.directory, task.join)
    assert before.ok

    os.remove(_persisted_pe(task))

    after = identity.run(task.directory, task.join)
    assert not after.ok
    assert any("not in the scene" in f or "autostart" in f
               for f in _new_fails(before, after)), _new_fails(before, after)


# --- Gate 3: strip the marker, or point an indicator somewhere real --------------------

def test_inertness_reddens_when_the_synthetic_marker_is_stripped(tmp_path):
    """MUTATION: blank the ARTIFACTFORGE-SYNTHETIC- overlay anchor in every PE."""
    task = _windows(tmp_path)
    before = inertness.run(task.directory)

    for name in os.listdir(task.directory):
        p = os.path.join(task.directory, name)
        with open(p, "rb") as f:
            data = f.read()
        if data[:2] == b"MZ":
            with open(p, "wb") as f:
                f.write(data.replace(b"ARTIFACTFORGE-SYNTHETIC-", b"\x00" * 24))

    new = _new_fails(before, inertness.run(task.directory))
    assert any("synthetic marker" in f for f in new), new


def test_inertness_reddens_when_an_indicator_could_be_real(tmp_path):
    """MUTATION: put a routable, non-reserved domain into an artifact."""
    task = _windows(tmp_path)
    before = inertness.run(task.directory)

    with open(_persisted_pe(task), "ab") as f:
        f.write(b"https://real-company-cdn.co.uk/payload")

    new = _new_fails(before, inertness.run(task.directory))
    assert any("RFC 2606" in f for f in new), new


def test_inertness_reddens_when_the_code_section_is_not_inert(tmp_path):
    """MUTATION: write real instructions after the ret."""
    task = _windows(tmp_path)
    before = inertness.run(task.directory)

    path = _persisted_pe(task)
    with open(path, "rb") as f:
        data = bytearray(f.read())
    data[0x401:0x405] = b"\x48\x31\xc0\x90"          # xor rax,rax ; nop — past the ret
    with open(path, "wb") as f:
        f.write(bytes(data))

    new = _new_fails(before, inertness.run(task.directory))
    assert any("not inert" in f for f in new), new


def test_inertness_reddens_when_pe_entry_point_skips_ret(tmp_path):
    """MUTATION: keep a parseable PE and its inert bytes, but enter after the return."""
    import pefile

    task = _windows(tmp_path)
    before = inertness.run(task.directory)
    assert before.ok
    path = _persisted_pe(task)
    parsed = pefile.PE(path)
    entry_offset = parsed.OPTIONAL_HEADER.get_field_absolute_offset("AddressOfEntryPoint")
    with open(path, "r+b") as file:
        file.seek(entry_offset)
        file.write(struct.pack("<I", parsed.OPTIONAL_HEADER.AddressOfEntryPoint + 1))

    assert pefile.PE(path).NT_HEADERS.Signature == 0x4550
    after = inertness.run(task.directory)
    assert (after.metrics["binary_safety_checks_passed"]
            == after.metrics["binary_safety_checks_total"] - 1)
    new = _new_fails(before, after)
    assert any("AddressOfEntryPoint" in failure for failure in new), new


def test_inertness_reddens_when_pe_imports_an_unmodeled_dll(tmp_path):
    """MUTATION: a loaded DLL can run before entry, so its name is part of safety policy."""
    import pefile

    task = _windows(tmp_path)
    before = inertness.run(task.directory)
    path = _persisted_pe(task)
    with open(path, "rb") as file:
        data = file.read()
    assert b"kernel32.dll" in data
    with open(path, "wb") as file:
        file.write(data.replace(b"kernel32.dll", b"evil0000.dll", 1))

    assert pefile.PE(path).DIRECTORY_ENTRY_IMPORT[0].dll == b"evil0000.dll"
    new = _new_fails(before, inertness.run(task.directory))
    assert any("system DLL imports" in failure for failure in new), new


def test_inertness_reddens_when_the_dos_stub_is_tampered_with(tmp_path):
    """MUTATION: replace the standard MS-DOS stub with different 16-bit code.

    The stub is the one region of a PE where arbitrary code is conventional and nothing
    reads it, so it is the obvious place to hide something. The gate requires it byte-exact.
    """
    task = _windows(tmp_path)
    before = inertness.run(task.directory)

    path = _persisted_pe(task)
    with open(path, "rb") as f:
        data = bytearray(f.read())
    data[0x40:0x44] = b"\xb8\x00\x4c\xcd"          # different real-mode code
    with open(path, "wb") as f:
        f.write(bytes(data))

    new = _new_fails(before, inertness.run(task.directory))
    assert any("MS-DOS stub" in f for f in new), new


def test_inertness_reddens_when_dos_entry_registers_change(tmp_path):
    """MUTATION: redirect 16-bit execution while retaining the familiar DOS-stub bytes."""
    task = _windows(tmp_path)
    before = inertness.run(task.directory)
    path = _persisted_pe(task)
    with open(path, "r+b") as file:
        file.seek(0x14)  # e_ip
        file.write(struct.pack("<H", 0x10))

    import pefile

    assert pefile.PE(path).NT_HEADERS.Signature == 0x4550
    new = _new_fails(before, inertness.run(task.directory))
    assert any("MS-DOS stub and header" in failure for failure in new), new


def test_inertness_reddens_when_a_bundle_id_names_a_real_vendor(tmp_path):
    """MUTATION: give a LaunchAgent a real vendor's reverse-DNS identifier.

    On macOS the bundle identifier is embedded in the code signature, so an ad-hoc-signed
    synthetic binary calling itself com.apple.Notes asserts something false about Apple. Every
    other indicator class is policed on the emitted bytes; this one was not, and the samples
    shipped exactly that until it was.
    """
    from artifactforge.artifacts.macos import build_launch_agent

    task = _macos(tmp_path, "vendor")
    before = inertness.run(task.directory)

    with open(os.path.join(task.directory, "com.apple.notes.plist"), "wb") as f:
        f.write(build_launch_agent("com.apple.notes", "/tmp/x"))

    new = _new_fails(before, inertness.run(task.directory))
    assert any("real vendor" in f for f in new), new


def _subject_macho(task):
    return os.path.join(task.directory, task.join["subject"]["bundle_id"])


def _macho_command(data: bytes, wanted: int) -> int:
    ncmds = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    for _ in range(ncmds):
        command, size = struct.unpack_from("<II", data, offset)
        if command == wanted:
            return offset
        offset += size
    raise AssertionError(f"load command {wanted:#x} not found")


def _macho_text_offset(data: bytes) -> int:
    ncmds = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    for _ in range(ncmds):
        command, size = struct.unpack_from("<II", data, offset)
        if command == 0x19:  # LC_SEGMENT_64
            nsects = struct.unpack_from("<I", data, offset + 64)[0]
            section_offset = offset + 72
            for _section in range(nsects):
                name = data[section_offset:section_offset + 16].rstrip(b"\x00")
                segment = data[section_offset + 16:section_offset + 32].rstrip(b"\x00")
                if (segment, name) == (b"__TEXT", b"__text"):
                    return struct.unpack_from("<I", data, section_offset + 48)[0]
                section_offset += 80
        offset += size
    raise AssertionError("__TEXT,__text not found")


def _macho_section_header_offset(data: bytes, wanted_segment: bytes, wanted_name: bytes) -> int:
    ncmds = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    for _ in range(ncmds):
        command, size = struct.unpack_from("<II", data, offset)
        if command == 0x19:  # LC_SEGMENT_64
            nsects = struct.unpack_from("<I", data, offset + 64)[0]
            section_offset = offset + 72
            for _section in range(nsects):
                name = data[section_offset:section_offset + 16].rstrip(b"\x00")
                segment = data[section_offset + 16:section_offset + 32].rstrip(b"\x00")
                if (segment, name) == (wanted_segment, wanted_name):
                    return section_offset
                section_offset += 80
        offset += size
    raise AssertionError(f"section {wanted_segment!r},{wanted_name!r} not found")


def _rehash_macho_code_slots(data: bytearray) -> None:
    signature_command = _macho_command(data, 0x1D)
    signature_offset = struct.unpack_from("<I", data, signature_command + 8)[0]
    count = struct.unpack_from(">I", data, signature_offset + 8)[0]
    for index in range(count):
        slot, relative_offset = struct.unpack_from(">II", data, signature_offset + 12 + index * 8)
        if slot != 0:
            continue
        code_directory = signature_offset + relative_offset
        hash_offset = struct.unpack_from(">I", data, code_directory + 16)[0]
        n_code = struct.unpack_from(">I", data, code_directory + 28)[0]
        code_limit = struct.unpack_from(">I", data, code_directory + 32)[0]
        hash_size = data[code_directory + 36]
        page_size = 1 << data[code_directory + 39]
        for page in range(n_code):
            start = page * page_size
            digest = hashlib.sha256(data[start:min(start + page_size, code_limit)]).digest()
            target = code_directory + hash_offset + page * hash_size
            data[target:target + hash_size] = digest
        return
    raise AssertionError("CodeDirectory slot not found")


def _assert_macho_remains_parseable(path):
    """The mutation changes meaning, not the outer format read by Gate 1's two oracles."""
    import lief
    from macholib.MachO import MachO

    assert lief.parse(path) is not None
    assert MachO(path).headers


def test_inertness_reddens_when_macho_entry_skips_the_exit_status_instruction(tmp_path):
    """MUTATION: LC_MAIN points at ``ret`` while the permitted bytes remain elsewhere.

    A substring search stays green under this mutation. A structural safety proof must bind
    the declared entry point to the first instruction of the only executable section.
    """
    task = _macos(tmp_path, "macho-entry")
    before = inertness.run(task.directory)
    assert before.ok
    assert (before.metrics["binary_safety_checks_passed"]
            == before.metrics["binary_safety_checks_total"])
    path = _subject_macho(task)
    with open(path, "rb") as f:
        data = bytearray(f.read())
    main_offset = _macho_command(data, 0x80000028)  # LC_MAIN
    entryoff = struct.unpack_from("<Q", data, main_offset + 8)[0]
    struct.pack_into("<Q", data, main_offset + 8, entryoff + 4)
    with open(path, "wb") as f:
        f.write(data)

    _assert_macho_remains_parseable(path)
    after = inertness.run(task.directory)
    assert (after.metrics["binary_safety_checks_passed"]
            == after.metrics["binary_safety_checks_total"] - 1)
    new = _new_fails(before, after)
    assert any("LC_MAIN points" in failure for failure in new), new


def test_inertness_reddens_when_macho_entry_code_changes_semantics(tmp_path):
    """MUTATION: change ``mov w0,#0`` to the parseable ``mov w0,#1`` instruction."""
    task = _macos(tmp_path, "macho-code")
    before = inertness.run(task.directory)
    assert before.ok
    assert (before.metrics["binary_safety_checks_passed"]
            == before.metrics["binary_safety_checks_total"])
    path = _subject_macho(task)
    with open(path, "rb") as f:
        data = bytearray(f.read())
    text_offset = _macho_text_offset(data)
    data[text_offset:text_offset + 4] = b"\x20\x00\x80\x52"  # mov w0, #1
    with open(path, "wb") as f:
        f.write(data)

    _assert_macho_remains_parseable(path)
    after = inertness.run(task.directory)
    assert (after.metrics["binary_safety_checks_passed"]
            == after.metrics["binary_safety_checks_total"] - 1)
    new = _new_fails(before, after)
    assert any("entry bytes" in failure for failure in new), new


def test_inertness_reddens_when_macho_signature_stops_covering_the_file(tmp_path):
    """MUTATION: shorten CodeDirectory's codeLimit by one, leaving a parseable Mach-O."""
    task = _macos(tmp_path, "macho-signature")
    before = inertness.run(task.directory)
    assert before.ok
    assert (before.metrics["binary_safety_checks_passed"]
            == before.metrics["binary_safety_checks_total"])
    path = _subject_macho(task)
    with open(path, "rb") as f:
        data = bytearray(f.read())
    signature_command = _macho_command(data, 0x1D)  # LC_CODE_SIGNATURE
    signature_offset = struct.unpack_from("<I", data, signature_command + 8)[0]
    count = struct.unpack_from(">I", data, signature_offset + 8)[0]
    code_directory = None
    for index in range(count):
        slot, relative_offset = struct.unpack_from(">II", data, signature_offset + 12 + index * 8)
        if slot == 0:
            code_directory = signature_offset + relative_offset
            break
    assert code_directory is not None
    struct.pack_into(">I", data, code_directory + 32, signature_offset - 1)
    with open(path, "wb") as f:
        f.write(data)

    _assert_macho_remains_parseable(path)
    after = inertness.run(task.directory)
    assert (after.metrics["binary_safety_checks_passed"]
            == after.metrics["binary_safety_checks_total"] - 1)
    new = _new_fails(before, after)
    assert any("coverage does not end" in failure for failure in new), new


def test_inertness_reddens_when_macho_got_becomes_an_initializer_table(tmp_path):
    """MUTATION: make bound pointers pre-main initializers, then repair signature hashes."""
    task = _macos(tmp_path, "macho-initializer")
    before = inertness.run(task.directory)
    assert before.ok
    path = _subject_macho(task)
    with open(path, "rb") as file:
        data = bytearray(file.read())
    got = _macho_section_header_offset(data, b"__DATA_CONST", b"__got")
    struct.pack_into("<I", data, got + 64, 0x9)  # S_MOD_INIT_FUNC_POINTERS
    _rehash_macho_code_slots(data)
    with open(path, "wb") as file:
        file.write(data)

    _assert_macho_remains_parseable(path)
    after = inertness.run(task.directory)
    assert (after.metrics["binary_safety_checks_passed"]
            == after.metrics["binary_safety_checks_total"] - 1)
    new = _new_fails(before, after)
    assert any("section profile" in failure for failure in new), new


# --- Gate 4: both directions, and the control -----------------------------------------

def test_solvability_reddens_when_an_answer_is_not_in_the_evidence(tmp_path):
    """MUTATION: replace one expected answer with a value no artifact contains."""
    holdout = _suite(tmp_path, "h", n=2, key=HOLDOUT_KEY)
    dev = _suite(tmp_path, "d", n=2)
    # Gate 4 is legitimately RED: the footprint adversary scores far above its threshold and
    # the gate is reporting that truthfully. So this compares NEW failures rather than
    # asserting prior greenness — the mutation still has to be the thing that adds one.
    before = solvability.run(holdout, dev)

    win = next(t for t in holdout if t.family == "windows")
    win.questions[0] = dataclasses.replace(win.questions[0], expected="0" * 64)

    after = solvability.run(holdout, dev)
    assert not after.ok
    assert any("reference solver" in f for f in _new_fails(before, after))


def test_solvability_reddens_when_a_question_stops_requiring_a_join(tmp_path):
    """MUTATION: mark every macOS question as answerable from one artifact."""
    holdout = _suite(tmp_path, "h", n=2, key=HOLDOUT_KEY)
    dev = _suite(tmp_path, "d", n=2)
    before = solvability.run(holdout, dev)

    for t in holdout:
        if t.family == "macos":
            t.questions = [dataclasses.replace(q, joins=1) for q in t.questions]

    new = _new_fails(before, solvability.run(holdout, dev))
    assert any("requires joining two artifacts" in f for f in new), new


def test_solvability_reddens_when_the_blind_adversary_is_broken(tmp_path):
    """MUTATION: hand the control a suite the blind adversary cannot cheat.

    Without this the negative direction passes vacuously: an adversary that always returns
    nothing scores 0% against the hold-out suite and looks like proof of security.
    """
    holdout = _suite(tmp_path, "h", n=2, key=HOLDOUT_KEY)
    dev = _suite(tmp_path, "d", n=2)
    before = solvability.run(holdout, dev)

    broken_control = _suite(tmp_path, "h2", n=2, key=HOLDOUT_KEY)   # not a dev suite at all
    after = solvability.run(holdout, broken_control)
    assert any("it is broken" in f for f in _new_fails(before, after)), after.fails


def _macos(tmp_path, name="m"):
    return next(t for t in _suite(tmp_path, name) if t.family == "macos")


def test_validity_reddens_when_raw_sqlite_header_constraints_are_violated(tmp_path):
    """MUTATION: reserved header byte 72 is non-zero; sqlite3 still accepts the database."""
    task = _macos(tmp_path, "sqlite-header")
    before = validity.run(task.directory)
    assert before.ok
    path = os.path.join(task.directory, "knowledgeC.db")
    with open(path, "rb") as file:
        data = bytearray(file.read())
    data[72] = 1
    assert validity._read_sqlite3(bytes(data)).tables
    with open(path, "wb") as file:
        file.write(data)

    new = _new_fails(before, validity.run(task.directory))
    assert any("sqlite-raw rejected" in failure for failure in new), new


def test_validity_reddens_when_unallocated_sqlite_bytes_hide_payload(tmp_path):
    """MUTATION: sqlite3 ignores non-zero page slack; the exact raw profile must not."""
    task = _macos(tmp_path, "sqlite-slack")
    before = validity.run(task.directory)
    assert before.ok
    path = os.path.join(task.directory, "knowledgeC.db")
    with open(path, "rb") as file:
        data = bytearray(file.read())
    page = 4096
    header = page
    cell_count = int.from_bytes(data[header + 3:header + 5], "big")
    pointer_end = header + 8 + 2 * cell_count
    content_start = page + int.from_bytes(data[header + 5:header + 7], "big")
    payload = b"PAYLOAD-UNALLOCATED-NOT-PARSED"
    assert pointer_end + len(payload) < content_start
    data[pointer_end:pointer_end + len(payload)] = payload
    assert validity._read_sqlite3(bytes(data)).tables
    with open(path, "wb") as file:
        file.write(data)

    new = _new_fails(before, validity.run(task.directory))
    assert any("sqlite-raw rejected" in failure for failure in new), new


def test_validity_reddens_when_bplist_reserved_trailer_bytes_are_nonzero(tmp_path):
    """MUTATION: plistlib accepts a trailer value outside the canonical raw subset."""
    task = _macos(tmp_path, "plist-trailer")
    before = validity.run(task.directory)
    assert before.ok
    name = f"{task.join['subject']['bundle_id']}.plist"
    path = os.path.join(task.directory, name)
    with open(path, "rb") as file:
        data = bytearray(file.read())
    data[-32] = 1
    assert validity._read_plistlib(bytes(data)).value["RunAtLoad"] is True
    with open(path, "wb") as file:
        file.write(data)

    new = _new_fails(before, validity.run(task.directory))
    assert any("bplist-raw rejected" in failure for failure in new), new


def test_validity_reddens_on_tcc_meaning_even_when_both_parsers_agree(tmp_path):
    """MUTATION: auth_value 1 is valid SQLite but outside the modeled TCC semantics."""
    import sqlite3

    task = _macos(tmp_path, "tcc-profile")
    before = validity.run(task.directory)
    assert before.ok
    path = os.path.join(task.directory, "TCC.db")
    con = sqlite3.connect(path)
    try:
        # 0 and 1 both use a zero-byte SQLite serial payload, preserving canonical tiling.
        con.execute("UPDATE access SET auth_value=1 WHERE rowid=3")
        con.commit()
    finally:
        con.close()

    new = _new_fails(before, validity.run(task.directory))
    assert any("macos-sqlite-profile" in failure for failure in new), new
    assert not any("sqlite-consensus" in failure or "rejected it" in failure for failure in new)


def test_validity_reddens_on_plist_type_even_when_both_parsers_agree(tmp_path):
    """MUTATION: integer 1 compares equal to True in Python but is not a plist boolean."""
    import plistlib

    task = _macos(tmp_path, "plist-profile")
    before = validity.run(task.directory)
    assert before.ok
    name = f"{task.join['subject']['bundle_id']}.plist"
    path = os.path.join(task.directory, name)
    with open(path, "rb") as file:
        value = plistlib.load(file)
    value["RunAtLoad"] = 1
    with open(path, "wb") as file:
        plistlib.dump(value, file, fmt=plistlib.FMT_BINARY, sort_keys=True)

    new = _new_fails(before, validity.run(task.directory))
    assert any("launchagent-profile" in failure for failure in new), new
    assert not any("bplist-consensus" in failure or "rejected it" in failure for failure in new)


def test_validity_reddens_when_sqlite_artifact_names_are_swapped(tmp_path):
    """MUTATION: both databases remain valid, but their names now assert the wrong profile."""
    task = _macos(tmp_path, "sqlite-names")
    before = validity.run(task.directory)
    assert before.ok
    left = os.path.join(task.directory, "TCC.db")
    right = os.path.join(task.directory, "knowledgeC.db")
    temporary = os.path.join(task.directory, ".swap.db")
    os.replace(left, temporary)
    os.replace(right, left)
    os.replace(temporary, right)

    new = _new_fails(before, validity.run(task.directory))
    profile_failures = [failure for failure in new if "macos-sqlite-profile" in failure]
    assert len(profile_failures) == 2, new
    assert not any("sqlite-consensus" in failure or "rejected it" in failure for failure in new)


def test_identity_reddens_when_the_macho_no_longer_matches_the_scene(tmp_path):
    """MUTATION: append one byte to the subject's Mach-O.

    The macOS half of the keystone. Before this landed the gate carried a declared gap
    saying macOS scenes had no hash-shaped field at all, so there was nothing here to break.
    """
    task = _macos(tmp_path)
    before = identity.run(task.directory, task.join)
    assert before.ok, f"gate 2 must be green before the mutation:\n{before.render()}"

    with open(os.path.join(task.directory, task.join["subject"]["bundle_id"]), "ab") as f:
        f.write(b"\x00")

    after = identity.run(task.directory, task.join)
    assert not after.ok
    new = _new_fails(before, after)
    assert any("sha256" in f for f in new), new


def test_identity_reddens_when_the_quarantine_uuid_join_is_broken(tmp_path):
    """MUTATION: point the subject's xattr at a UUID no quarantine row carries."""
    task = _macos(tmp_path)
    before = identity.run(task.directory, task.join)
    assert before.ok

    path = os.path.join(task.directory,
                        f"{task.join['subject']['bundle_id']}.quarantine.xattr")
    with open(path) as f:
        head = f.read().rsplit(";", 1)[0]
    with open(path, "w") as f:
        f.write(head + ";00000000-0000-4000-8000-000000000000")

    after = identity.run(task.directory, task.join)
    assert not after.ok
    assert any("quarantine UUID" in f or "matches no row" in f
               for f in _new_fails(before, after)), _new_fails(before, after)
