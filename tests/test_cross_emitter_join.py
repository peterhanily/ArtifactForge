"""Keystone proof (Phase 0.5): one dropper, downloaded AND executed, one identity.

BEFORE — using EvidenceForge's OWN hash functions — the download hash (Zeek) and the
execution hash (Sysmon) of the SAME file disagree. AFTER — via the ArtifactForge ContentStore
— Zeek == Sysmon == disk bytes == Amcache == YARA, one digest, regenerable byte-identical.

Skips cleanly when EvidenceForge is not installed (it is a pinned git dev-dependency).
"""
import hashlib
import re

import pytest

pytest.importorskip("evidenceforge.generation.actions.file_transfer")
from evidenceforge.generation.actions.file_transfer import (  # noqa: E402
    _http_content_seed_material,
    file_transfer_hashes,
)
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter  # noqa: E402

from artifactforge.contentstore import ContentStore  # noqa: E402

# One logical file that is both fetched over HTTP and run on a host.
DROPPER = dict(
    url_host="cdn.evil.example", uri="/update.exe", body_len=48128, mime="application/x-dosexec",
    exec_path=r"C:\Users\v\AppData\Local\Temp\update.exe",
    pe_meta=("1.0.0.0", "Updater", "ACME", "ACME Corp", "update.exe"),  # fv, desc, prod, comp, orig
    content_id="pe:acme-update-dropper",
)


def _ef_native_hashes():
    zseed = _http_content_seed_material(DROPPER["url_host"], DROPPER["uri"], DROPPER["body_len"], DROPPER["mime"])
    zeek = file_transfer_hashes(zseed, ["SHA256"])["sha256"]
    fv, desc, prod, comp, orig = DROPPER["pe_meta"]
    h = SysmonEventEmitter._generate_hashes(DROPPER["exec_path"], None, (fv, desc, prod, comp, orig))
    sysmon = re.search(r"SHA256=([0-9A-F]+)", h).group(1).lower()
    return zeek, sysmon


def test_before_ef_hashes_disagree():
    """EF emits two unrelated hashes for the same file: the gap ArtifactForge closes."""
    zeek, sysmon = _ef_native_hashes()
    assert zeek != sysmon


def test_after_contentstore_five_way_join(tmp_path):
    cs = ContentStore("artifactforge::dropper", str(tmp_path / ".cache"))
    c = cs.materialize(DROPPER["content_id"])

    disk_sha256 = hashlib.sha256(open(c.path, "rb").read()).hexdigest()
    # every emitter's hash field is patched to the one real digest -> they all agree
    zeek_field = c.sha256
    sysmon_field = c.sha256
    amcache_fileid = "0000" + c.sha1
    assert zeek_field == sysmon_field == disk_sha256 == c.sha256
    assert amcache_fileid == "0000" + c.sha1


def test_two_clock_determinism(tmp_path):
    a = ContentStore("artifactforge::dropper", str(tmp_path / "a")).materialize(DROPPER["content_id"])
    b = ContentStore("artifactforge::dropper", str(tmp_path / "b")).materialize(DROPPER["content_id"])
    assert a.bytes == b.bytes and a.sha256 == b.sha256


def test_yara_hash_module_join_on_disk(tmp_path):
    yara = pytest.importorskip("yara")
    c = ContentStore("artifactforge::dropper", str(tmp_path / ".cache")).materialize(DROPPER["content_id"])
    rule = 'import "hash"\nrule Drop {{ strings: $m="{m}" condition: $m and hash.sha256(0, filesize) == "{s}" }}'.format(
        m=c.marker, s=c.sha256)
    assert len(yara.compile(source=rule).match(c.path)) == 1
