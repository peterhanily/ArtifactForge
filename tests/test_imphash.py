# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Step 1 proof: the synthetic PE carries a REAL, deterministic IMPHASH.

Our pure-stdlib imphash_of() must equal what pefile computes from the assembled bytes,
so the IMPHASH that appears in Sysmon / Amcache / Zeek's PE analyzer is a genuine digest
of a real import table — not a placeholder — and is stable across regenerations.
"""
import pytest

from artifactforge.content.store import ContentStore, _sub_seed, imphash_of


def _content_seed(scenario, cid):
    return _sub_seed(_sub_seed(scenario.encode(), "contentstore"), cid)


def test_imphash_matches_pefile(tmp_path):
    pefile = pytest.importorskip("pefile")
    cs = ContentStore("artifactforge::imphash", str(tmp_path / ".cache"))
    for cid in ("pe:alpha", "pe:bravo", "pe:charlie"):
        c = cs.materialize(cid)
        pe = pefile.PE(data=c.bytes)
        assert pe.get_imphash() == c.imphash          # our value == real parser's value
        assert c.imphash != "0" * 32 and c.imphash     # a real, non-empty hash


def test_imphash_deterministic_and_varies(tmp_path):
    a1 = ContentStore("artifactforge::imphash", str(tmp_path / "a")).materialize("pe:alpha")
    a2 = ContentStore("artifactforge::imphash", str(tmp_path / "b")).materialize("pe:alpha")
    other = ContentStore("artifactforge::imphash", str(tmp_path / "c")).materialize("pe:bravo")
    assert a1.imphash == a2.imphash and a1.bytes == a2.bytes   # deterministic
    assert a1.imphash != other.imphash                          # varies by content id


def test_imphash_of_pure_function():
    imports = [("KERNEL32.dll", ["CreateFileA", "ExitProcess"]), ("WS2_32.dll", ["socket"])]
    # extension stripped, names lowercased, comma-joined, md5 — same rule as pefile
    import hashlib
    expected = hashlib.md5(b"kernel32.createfilea,kernel32.exitprocess,ws2_32.socket").hexdigest()
    assert imphash_of(imports) == expected


def test_fixed_size_pe_profile_survives_both_parsers_and_gate3(tmp_path):
    """Variable imports must never turn file length into a benchmark role signal."""
    import lief
    import pefile

    from artifactforge.gates import inertness

    store = ContentStore("artifactforge::fixed-pe-profile", str(tmp_path / "cache"))
    scene = tmp_path / "scene"
    scene.mkdir()
    lengths = set()
    for index in range(128):
        content = store.materialize(f"pe:profile-{index:03d}")
        lengths.add(len(content.bytes))
        assert pefile.PE(data=content.bytes).get_imphash() == content.imphash
        assert lief.parse(content.path) is not None
        (scene / f"candidate-{index:03d}.exe").write_bytes(content.bytes)

    assert lengths == {2729}
    report = inertness.run(str(scene))
    assert report.ok, report.render()
    assert report.metrics["binary_safety_checks_passed"] == 128
    assert report.metrics["binary_safety_checks_total"] == 128
