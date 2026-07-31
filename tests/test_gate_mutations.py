"""The mutation register — the sixth binding, and the one that makes the rest mean anything.

Every gate ships with a named mutation that must turn it red. A gate never observed to fail
proves nothing, and this repository has the receipts: `tests/test_real_run_join.py` asserted
`amcache == "0000" + c.sha1` one line after assigning exactly that, and stayed green when the
hash it was supposedly checking was replaced with the string GARBAGE-NOT-A-SHA1.

Each test below compares the gate's failures before and after the mutation and requires a
NEW failure naming the thing that was broken. Comparing before-and-after rather than simply
asserting `not ok` matters, because several gates are legitimately red already — a mutation
test that only checked redness would pass without the mutation doing anything at all.
"""
import hashlib
import os

import pytest

from artifactforge.bench.benchmark import generate_batch, grade
from artifactforge.bench.reference_solver import reference_solve
from artifactforge.gates import identity, inertness, solvability, validity

pytest.importorskip("pefile")
pytest.importorskip("regipy")
pytest.importorskip("windowsprefetch")


def _new_fails(before, after):
    return [f for f in after.fails if f not in before.fails]


def _windows_scene(tmp_path, name="b"):
    tasks = generate_batch(2, str(tmp_path / name))
    return next(t for t in tasks if t.family == "windows")


def _pe_in(directory):
    for f in sorted(os.listdir(directory)):
        p = os.path.join(directory, f)
        if os.path.isfile(p) and open(p, "rb").read(2) == b"MZ":
            return p
    raise AssertionError("no PE in scene")


# --- Gate 1: corrupt an artifact and its parser must refuse it ------------------------

def test_validity_reddens_when_an_artifact_is_corrupted(tmp_path):
    """MUTATION: truncate Amcache.hve to 200 bytes. regipy must reject it."""
    task = _windows_scene(tmp_path)
    before = validity.run(task.directory)

    hive = os.path.join(task.directory, "Amcache.hve")
    with open(hive, "r+b") as f:
        f.truncate(200)

    after = validity.run(task.directory)
    new = _new_fails(before, after)
    assert any("regipy rejected" in f for f in new), \
        f"a truncated hive did not fail Gate 1. new fails: {new}"


# --- Gate 2: break the pivot and the identity gate must notice ------------------------

def test_identity_reddens_when_the_pe_no_longer_matches_its_manifest(tmp_path):
    """MUTATION: append one byte to the PE. Every digest in the manifest is now wrong."""
    task = _windows_scene(tmp_path)
    before = identity.run(task.directory)
    assert before.ok, f"gate 2 must be green before the mutation:\n{before.render()}"

    pe = _pe_in(task.directory)
    with open(pe, "ab") as f:
        f.write(b"\x00")

    after = identity.run(task.directory)
    assert not after.ok
    assert any("sha256" in f for f in _new_fails(before, after))


def test_identity_reddens_when_the_amcache_hash_join_is_destroyed(tmp_path):
    """MUTATION: rewrite Amcache's FileId to a different file's SHA1.

    This is the exact failure the predecessor test could not see: the registry still parses,
    the manifest is untouched, and only the *cross-artifact* claim is false.
    """
    from artifactforge.artifacts.hive import build_amcache_hive

    task = _windows_scene(tmp_path)
    before = identity.run(task.directory)
    assert before.ok

    wrong = hashlib.sha1(b"a different file entirely").hexdigest()  # noqa: S324
    with open(os.path.join(task.directory, "Amcache.hve"), "wb") as f:
        f.write(build_amcache_hive(wrong, "c:\\x.exe", "x.exe", 1))

    after = identity.run(task.directory)
    assert not after.ok
    assert any("FileId" in f for f in _new_fails(before, after)), _new_fails(before, after)


# --- Gate 3: strip the marker, or point an indicator somewhere real --------------------

def test_inertness_reddens_when_the_synthetic_marker_is_stripped(tmp_path):
    """MUTATION: blank the PE's ARTIFACTFORGE-SYNTHETIC- overlay anchor."""
    task = _windows_scene(tmp_path)
    before = inertness.run(task.directory)

    pe = _pe_in(task.directory)
    data = open(pe, "rb").read().replace(b"ARTIFACTFORGE-SYNTHETIC-", b"\x00" * 24)
    with open(pe, "wb") as f:
        f.write(data)

    after = inertness.run(task.directory)
    assert any("synthetic marker" in f for f in _new_fails(before, after))


def test_inertness_reddens_when_an_indicator_could_be_real(tmp_path):
    """MUTATION: put a routable, non-reserved domain into an artifact."""
    task = _windows_scene(tmp_path)
    before = inertness.run(task.directory)

    pe = _pe_in(task.directory)
    with open(pe, "ab") as f:
        f.write(b"https://real-company-cdn.co.uk/payload")

    after = inertness.run(task.directory)
    assert any("RFC 2606" in f for f in _new_fails(before, after))


def test_inertness_reddens_when_the_code_section_is_not_inert(tmp_path):
    """MUTATION: write real instructions after the ret."""
    task = _windows_scene(tmp_path)
    before = inertness.run(task.directory)

    pe = _pe_in(task.directory)
    data = bytearray(open(pe, "rb").read())
    data[0x401:0x405] = b"\x48\x31\xc0\x90"          # xor rax,rax ; nop — past the ret
    with open(pe, "wb") as f:
        f.write(bytes(data))

    after = inertness.run(task.directory)
    assert any("not inert" in f for f in _new_fails(before, after))


# --- Gate 4: make an answer unrecoverable, and the positive direction must notice ------

def test_solvability_reddens_when_an_answer_is_not_in_the_evidence(tmp_path):
    """MUTATION: replace one expected answer with a value no artifact contains."""
    import dataclasses

    tasks = generate_batch(2, str(tmp_path / "b"))
    before = solvability.run(tasks)

    win = next(t for t in tasks if t.family == "windows")
    win.questions[0] = dataclasses.replace(win.questions[0], expected="0" * 64)

    after = solvability.run(tasks)
    assert after.metrics["reference_solver_score"] < before.metrics["reference_solver_score"]
    assert any("reference solver" in f for f in _new_fails(before, after))


def test_solvability_sees_the_blind_adversary(tmp_path):
    """The benchmark's current, real state: a solver opening zero files reproduces answers.

    Recorded as a test rather than a note so that when Phase 2 splits the public identifier
    from the generation seed, this test fails and must be updated deliberately — the number
    cannot improve silently, and it cannot regress silently either.
    """
    tasks = generate_batch(4, str(tmp_path / "b"))
    r = solvability.run(tasks)
    blind = r.metrics["blind_solver_score"]
    assert blind == pytest.approx(1.0), (
        f"the blind adversary scores {blind:.1%}. If this dropped, the seed/identifier "
        f"split has landed — update this test and the scorecard baseline together.")
    assert any("blind" in f for f in r.fails)


def test_reference_solver_still_reads_real_artifacts(tmp_path):
    """Guard against the mutations above leaking into the positive direction."""
    task = _windows_scene(tmp_path, name="clean")
    assert grade(task, reference_solve(task)).accuracy == 1.0
