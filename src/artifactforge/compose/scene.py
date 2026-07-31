"""Compose a coherent Windows crime scene from ONE canonical file identity.

A single dropped binary appears as: the PE itself (real bytes + IMPHASH), a Run-key
persistence value, an Amcache execution record (FileId == the PE's SHA1), and a prefetch
file (execution evidence). Every hash-shaped field is a real digest of the one ContentStore
entry, so the cross-artifact join holds by construction — and the join manifest is the
machine-checkable answer key that ships in the box.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

from artifactforge.content.store import Content, ContentStore
from artifactforge.artifacts.hive import build_amcache_hive, build_run_hive
from artifactforge.artifacts.macos import (build_knowledgec, build_launch_agent, build_quarantine_events,
                           build_tcc, quarantine_xattr)
from artifactforge.artifacts.prefetch import build_prefetch, prefetch_name_hash
from artifactforge.model import PINNED_UNIX, HostProfile, deterministic_uuid


@dataclass
class CrimeScene:
    exec_path: str
    content: Optional[Content] = None               # the dropped PE (Windows scenes)
    artifacts: dict = field(default_factory=dict)   # filename -> filesystem path
    join: dict = field(default_factory=dict)        # the answer key


def _device_path(exec_path: str) -> str:
    tail = exec_path.split(":", 1)[-1] if ":" in exec_path else exec_path
    return "\\VOLUME{01}" + tail.upper()


def build_crime_scene(store: ContentStore, *, content_id: str, exec_path: str,
                      run_value_name: str, run_count: int, out_dir: str) -> CrimeScene:
    os.makedirs(out_dir, exist_ok=True)
    c = store.materialize(content_id)
    name = exec_path.replace("/", "\\").rsplit("\\", 1)[-1]
    dev = _device_path(exec_path)

    files = {
        name: c.bytes,
        "Software.run.hive": build_run_hive(run_value_name, exec_path),
        "Amcache.hve": build_amcache_hive(c.sha1, exec_path.lower(), name, len(c.bytes)),
        f"{name.upper()}-{prefetch_name_hash(dev):08X}.pf": build_prefetch(name, dev, run_count),
    }
    artifacts = {}
    for fname, data in files.items():
        p = os.path.join(out_dir, fname)
        with open(p, "wb") as f:
            f.write(data)
        artifacts[fname] = p

    join = {
        "content_id": content_id,
        "exec_path": exec_path,
        "exec_name": name,
        "run_count": run_count,
        "sha256": c.sha256,
        "sha1": c.sha1,
        "md5": c.md5,
        "imphash": c.imphash,
        "amcache_file_id": "0000" + c.sha1,
        "yara_marker": c.marker,
        # where the one identity surfaces (the join the responder pivots on)
        "appears_in": {
            "pe_bytes": "sha256 == disk file",
            "amcache": "InventoryApplicationFile.FileId[4:] == sha1",
            "run_key": "CurrentVersion\\Run value data == exec_path",
            "prefetch": "referenced file == exec_path",
        },
    }
    with open(os.path.join(out_dir, "JOIN_MANIFEST.json"), "w") as f:
        json.dump(join, f, indent=2)

    return CrimeScene(content=c, exec_path=exec_path, artifacts=artifacts, join=join)


def build_macos_crime_scene(profile: HostProfile, *, bundle_id: str, app_path: str,
                            download_url: str, origin_url: str, agent: str, out_dir: str) -> CrimeScene:
    """A coherent macOS scene from one app identity: downloaded (quarantine) -> granted TCC ->
    used (knowledgeC) -> persisted (LaunchAgent). Joined on the quarantine UUID + bundle id."""
    assert profile.os_family == "macos", "macOS scene needs a macOS profile"
    os.makedirs(out_dir, exist_ok=True)
    uuid = deterministic_uuid(profile.seed_tag() + ":" + bundle_id)
    t = profile.mac_abs_time()
    label = bundle_id

    files = {
        "knowledgeC.db": build_knowledgec(bundle_id, t, t + 120),
        "TCC.db": build_tcc(bundle_id, "kTCCServiceSystemPolicyAllFiles", t),
        "QuarantineEventsV2": build_quarantine_events(uuid, agent, download_url, origin_url, t),
        f"{label}.plist": build_launch_agent(label, app_path),
    }
    artifacts = {}
    for fname, data in files.items():
        p = os.path.join(out_dir, fname)
        with open(p, "wb") as f:
            f.write(data)
        artifacts[fname] = p
    # the quarantine xattr value (emitted as data — no real xattr is set on the host)
    xattr = quarantine_xattr(uuid, agent, PINNED_UNIX)
    xattr_path = os.path.join(out_dir, os.path.basename(app_path) + ".quarantine.xattr")
    with open(xattr_path, "w") as f:
        f.write(xattr)
    artifacts["quarantine_xattr"] = xattr_path

    join = {
        "os": f"{profile.os_family} {profile.version}",
        "bundle_id": bundle_id,
        "app_path": app_path,
        "quarantine_uuid": uuid,
        "quarantine_xattr": xattr,
        "download_url": download_url,
        "appears_in": {
            "quarantine_events": "LSQuarantineEventIdentifier == UUID",
            "quarantine_xattr": "xattr UUID field == LSQuarantineEventIdentifier",
            "tcc": "access.client == bundle_id (granted permission)",
            "knowledgeC": "ZOBJECT.ZVALUESTRING == bundle_id (app used)",
            "launch_agent": "ProgramArguments[0] == app_path (persistence)",
        },
    }
    with open(os.path.join(out_dir, "JOIN_MANIFEST.json"), "w") as f:
        json.dump(join, f, indent=2)

    return CrimeScene(exec_path=app_path, artifacts=artifacts, join=join)
