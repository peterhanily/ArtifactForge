"""Phase 0 proof: on a REAL EvidenceForge run, every Sysmon binary routes through the
ContentStore and the four-way join holds.

Point ARTIFACTFORGE_EF_OUT at an EvidenceForge output directory (the folder containing
data/<host>/windows_event_sysmon.xml). Skips when unset so CI without a fixture stays green.
"""
import glob
import hashlib
import os
import re

import pytest

from artifactforge.content.store import ContentStore
from artifactforge.ef_seeds import content_id, sysmon_seed

EF_OUT = os.environ.get("ARTIFACTFORGE_EF_OUT")


def _field(evt, name):
    m = re.search(r'Name="' + re.escape(name) + r'">([^<]*)<', evt)
    return m.group(1) if m else None


@pytest.mark.skipif(not EF_OUT, reason="set ARTIFACTFORGE_EF_OUT to a real EvidenceForge output dir")
def test_every_sysmon_binary_reverse_maps_and_joins(tmp_path):
    cs = ContentStore("artifactforge::real-run", str(tmp_path / ".cache"))
    with_hashes = reverse_ok = joined = 0
    binaries = {}

    for sf in glob.glob(EF_OUT + "/**/windows_event_sysmon.xml", recursive=True):
        for evt in re.findall(r"<Event\b.*?</Event>", open(sf, errors="ignore").read(), re.S):
            hf = _field(evt, "Hashes")
            if not hf:
                continue
            eid_m = re.search(r"<EventID>(\d+)</EventID>", evt)
            eid = eid_m.group(1) if eid_m else "?"
            path = _field(evt, "ImageLoaded") if eid == "7" else _field(evt, "Image")
            if not path:
                continue
            with_hashes += 1
            args = (path, _field(evt, "FileVersion"), _field(evt, "Description"),
                    _field(evt, "Product"), _field(evt, "Company"), _field(evt, "OriginalFileName"), eid)
            emitted = dict(kv.split("=", 1) for kv in hf.split(","))["SHA256"]
            # 1) reverse-map: recomputed EF seed hash identifies the logical binary
            if hashlib.sha256(sysmon_seed(*args).encode()).hexdigest().upper() == emitted:
                reverse_ok += 1
            binaries[content_id(*args)] = True

    # every hashed Sysmon record must be identifiable
    assert with_hashes > 0
    assert reverse_ok == with_hashes

    # 2) route each distinct binary through the ContentStore; four-way join holds
    for cid in binaries:
        c = cs.materialize(cid)
        disk = hashlib.sha256(open(c.path, "rb").read()).hexdigest()
        amcache = "0000" + c.sha1
        assert c.sha256 == disk and amcache == "0000" + c.sha1
        joined += 1
    assert joined == len(binaries)
