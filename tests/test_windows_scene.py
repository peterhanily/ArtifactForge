"""A Windows scene, read by the parsers a responder actually runs.

Every artifact is checked by an independent tool rather than by the code that wrote it, and
the decoys are checked too. A scene where every signal points at the same file cannot tell an
investigation from a lookup — a benchmark built on one scored 100% after its hash pivot had
been deliberately destroyed.
"""
import glob
import hashlib
import os

import pytest

from artifactforge import suite
from artifactforge.compose.scene import build_windows_scene
from artifactforge.content import ContentStore
from artifactforge.model import windows_profile

KEY = suite.scenario_key(suite.PUBLIC_DEV_KEY, "test-windows-scene")


def _scene(tmp_path, name="s"):
    store = ContentStore("artifactforge::test", str(tmp_path / "content"))
    return build_windows_scene(store, skey=KEY, profile=windows_profile(),
                               scene_dir=str(tmp_path / name / "scene"),
                               staging_dir=str(tmp_path / name / "staging"))


def _resident(d):
    out = {}
    for n in os.listdir(d):
        p = os.path.join(d, n)
        if os.path.isfile(p):
            with open(p, "rb") as f:
                data = f.read()
            if data[:2] == b"MZ":
                out[n.lower()] = data
    return out


def test_pe_imphash_is_real(tmp_path):
    pefile = pytest.importorskip("pefile")
    s = _scene(tmp_path)
    data = _resident(s.directory)[s.join["persisted"]["name"].lower()]
    assert pefile.PE(data=data).get_imphash() == s.join["persisted"]["imphash"]


def test_exactly_one_autostart_names_a_resident_program(tmp_path):
    RegistryHive = pytest.importorskip("regipy.registry").RegistryHive
    s = _scene(tmp_path)
    files = _resident(s.directory)
    run = RegistryHive(os.path.join(s.directory, "Software.run.hive")).get_key(
        "\\Microsoft\\Windows\\CurrentVersion\\Run")
    values = [v.value for v in run.get_values()]
    assert len(values) >= 3, "a single autostart makes the question a lookup"
    resident = [v for v in values if v.rsplit("\\", 1)[-1].lower() in files]
    assert resident == [s.join["persisted"]["path"]]


def test_exactly_one_amcache_hash_belongs_to_a_resident_file(tmp_path):
    RegistryHive = pytest.importorskip("regipy.registry").RegistryHive
    s = _scene(tmp_path)
    files = _resident(s.directory)
    by_sha1 = {hashlib.sha1(d).hexdigest(): n for n, d in files.items()}   # noqa: S324
    iaf = RegistryHive(os.path.join(s.directory, "Amcache.hve")).get_key(
        "\\Root\\InventoryApplicationFile")
    rows = [v.value for sub in iaf.iter_subkeys() for v in sub.get_values()
            if v.name == "FileId"]
    assert len(rows) >= 6, "a single Amcache row makes the hash pivot a lookup"
    matched = [by_sha1[r[4:]] for r in rows if r[4:] in by_sha1]
    assert matched == [s.join["amcache_match"]["name"].lower()]


def test_the_persisted_binary_is_recorded_under_a_stale_hash(tmp_path):
    """Following names and following hashes must reach different files, or neither is really
    a pivot — this is what makes the scene's two hash questions independent."""
    RegistryHive = pytest.importorskip("regipy.registry").RegistryHive
    s = _scene(tmp_path)
    persisted = s.join["persisted"]
    iaf = RegistryHive(os.path.join(s.directory, "Amcache.hve")).get_key(
        "\\Root\\InventoryApplicationFile")
    rows = {}
    for sub in iaf.iter_subkeys():
        v = {x.name: x.value for x in sub.get_values()}
        rows[v["LowerCaseLongPath"]] = v["FileId"][4:]
    assert persisted["path"].lower() in rows
    assert rows[persisted["path"].lower()] != persisted["sha1"]
    assert s.join["amcache_match"]["name"] != persisted["name"]


def test_prefetch_carries_execution_and_exactly_one_orphan(tmp_path):
    wp = pytest.importorskip("windowsprefetch")
    s = _scene(tmp_path)
    files = _resident(s.directory)
    counts = {}
    for pf_path in sorted(glob.glob(os.path.join(s.directory, "*.pf"))):
        pf = wp.Prefetch(pf_path)
        counts[pf.executableName.lower()] = pf.runCount
    assert len(counts) >= 4
    assert counts[s.join["persisted"]["name"].lower()] == s.join["persisted"]["run_count"]
    assert [n for n in counts if n not in files] == [s.join["orphan_execution"].lower()]


def test_only_the_allowlisted_files_are_served(tmp_path):
    """The served directory equals what we staged — no manifest, no content cache, no
    leftovers. Structural, not a filter: the previous design wrote the answer key into this
    directory and merely omitted it from a listing."""
    s = _scene(tmp_path)
    assert sorted(os.listdir(s.directory)) == s.artifacts
    assert not [f for f in s.artifacts if "MANIFEST" in f.upper()]
    assert not [f for f in s.artifacts if f.startswith(".")]


def test_two_clock_determinism(tmp_path):
    a, b = _scene(tmp_path, "a"), _scene(tmp_path, "b")
    assert a.artifacts == b.artifacts
    for name in a.artifacts:
        with open(os.path.join(a.directory, name), "rb") as fa, \
             open(os.path.join(b.directory, name), "rb") as fb:
            assert fa.read() == fb.read(), name
