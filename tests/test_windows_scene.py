# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
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


def test_five_amcache_hashes_form_a_bijection_over_resident_files(tmp_path):
    RegistryHive = pytest.importorskip("regipy.registry").RegistryHive
    s = _scene(tmp_path)
    files = _resident(s.directory)
    by_sha1 = {hashlib.sha1(d).hexdigest(): n for n, d in files.items()}   # noqa: S324
    iaf = RegistryHive(os.path.join(s.directory, "Amcache.hve")).get_key(
        "\\Root\\InventoryApplicationFile")
    rows = [
        {value.name: value.value for value in subkey.get_values()}
        for subkey in iaf.iter_subkeys()
    ]
    assert len(rows) == 8
    matched = {
        row["LowerCaseLongPath"]: by_sha1[row["FileId"][4:]]
        for row in rows if row["FileId"][4:] in by_sha1
    }
    assert len(matched) == len(files) == 5
    assert sorted(matched.values()) == sorted(files)

    relations = s.join["benchmark_relations"]
    assert len(relations) == 5
    for relation in relations:
        selector = relation["selector"]["lower_case_long_path"]
        assert matched[selector] == relation["candidate"].lower()
        data = files[relation["candidate"].lower()]
        assert hashlib.sha1(data).hexdigest() == relation["link_value"]  # noqa: S324
        assert hashlib.sha256(data).hexdigest() == relation["expected"]


def test_amcache_relation_has_no_name_or_size_shortcut(tmp_path):
    """Historical names never name current files and every resident has one file size."""
    RegistryHive = pytest.importorskip("regipy.registry").RegistryHive
    s = _scene(tmp_path)
    files = _resident(s.directory)
    assert {len(data) for data in files.values()} == {2729}
    iaf = RegistryHive(os.path.join(s.directory, "Amcache.hve")).get_key(
        "\\Root\\InventoryApplicationFile")
    rows = []
    record_keys = []
    for sub in iaf.iter_subkeys():
        record_keys.append(sub.name)
        rows.append({value.name: value.value for value in sub.get_values()})
    current_names = set(files)
    resident_sha1s = {hashlib.sha1(data).hexdigest() for data in files.values()}  # noqa: S324
    assert all(
        not any(sha1.startswith(record_key.removeprefix("0000")) for sha1 in resident_sha1s)
        for record_key in record_keys
    )
    for relation in s.join["benchmark_relations"]:
        selector = relation["selector"]["lower_case_long_path"]
        row = next(row for row in rows if row["LowerCaseLongPath"] == selector)
        assert row["Name"].lower() not in current_names
        assert selector.rsplit("\\", 1)[-1] not in current_names
        assert row["Size"] == 2729


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
