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

    with open(os.path.join(task.directory, "com.apple.Notes.plist"), "wb") as f:
        f.write(build_launch_agent("com.apple.Notes", "/tmp/x"))

    new = _new_fails(before, inertness.run(task.directory))
    assert any("real vendor" in f for f in new), new


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
