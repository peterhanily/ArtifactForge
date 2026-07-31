"""Step 2 proof: one dropped binary, a coherent Windows crime scene, real parsers.

The same ContentStore identity surfaces as a PE (real IMPHASH via pefile), a Run-key
persistence value (regipy), an Amcache execution record whose FileId is the PE's SHA1
(regipy), and a prefetch execution record (windowsprefetch) — and the cross-artifact join
holds. Each artifact is validated by an independent real DFIR parser (consistency-by-
construction), and the whole scene regenerates byte-identical (determinism gate).
"""
import pytest

from artifactforge.content.store import ContentStore
from artifactforge.compose.scene import build_crime_scene

PARAMS = dict(content_id="pe:acme-update-dropper",
              exec_path=r"C:\Users\v\AppData\Local\Temp\update.exe",
              run_value_name="Updater", run_count=3)


def _scene(tmp_path):
    store = ContentStore("artifactforge::crime-scene", str(tmp_path / ".cache"))
    return build_crime_scene(store, out_dir=str(tmp_path / "scene"), **PARAMS)


def test_pe_imphash_real(tmp_path):
    pefile = pytest.importorskip("pefile")
    s = _scene(tmp_path)
    pe = pefile.PE(data=s.content.bytes)
    assert pe.get_imphash() == s.content.imphash and s.content.imphash


def test_run_key_persistence(tmp_path):
    RegistryHive = pytest.importorskip("regipy.registry").RegistryHive
    s = _scene(tmp_path)
    run = RegistryHive(s.artifacts["Software.run.hive"]).get_key("\\Microsoft\\Windows\\CurrentVersion\\Run")
    values = {v.name: v.value for v in run.get_values()}
    assert values["Updater"] == PARAMS["exec_path"]


def test_amcache_carries_the_join(tmp_path):
    RegistryHive = pytest.importorskip("regipy.registry").RegistryHive
    s = _scene(tmp_path)
    iaf = RegistryHive(s.artifacts["Amcache.hve"]).get_key("\\Root\\InventoryApplicationFile")
    entry = next(iaf.iter_subkeys())
    vals = {v.name: v.value for v in entry.get_values()}
    assert vals["FileId"][4:] == s.content.sha1          # <- the host-side hash join
    assert vals["LowerCaseLongPath"] == PARAMS["exec_path"].lower()


def test_prefetch_execution_evidence(tmp_path):
    wp = pytest.importorskip("windowsprefetch")
    s = _scene(tmp_path)
    pf_path = next(p for k, p in s.artifacts.items() if k.endswith(".pf"))
    pf = wp.Prefetch(pf_path)
    assert pf.executableName == "UPDATE.EXE"
    assert pf.runCount == PARAMS["run_count"]
    assert any("UPDATE.EXE" in r for r in pf.resources)


def test_cross_artifact_join_manifest(tmp_path):
    s = _scene(tmp_path)
    assert s.join["amcache_file_id"] == "0000" + s.content.sha1
    assert s.join["sha256"] == s.content.sha256
    assert s.join["imphash"] == s.content.imphash


def test_two_clock_determinism(tmp_path):
    a = _scene(tmp_path / "a")
    b = _scene(tmp_path / "b")
    for kind in a.artifacts:
        assert open(a.artifacts[kind], "rb").read() == open(b.artifacts[kind], "rb").read()
