# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""A macOS scene — coverage EvidenceForge structurally cannot produce, since its os_category
is windows or linux and there is no macOS at all.

One app is the subject, and finding it requires reading two databases: several apps hold an
allowed TCC grant, several were used, and only one did both. Everything after that hangs off
the quarantine UUID, which is the join macOS actually gives a responder.
"""
import os
import plistlib
import sqlite3

from artifactforge import suite
from artifactforge.compose.scene import build_macos_scene
from artifactforge.content import ContentStore
from artifactforge.model import macos_profile

KEY = suite.scenario_key(suite.PUBLIC_DEV_KEY, "test-macos-scene")


def _scene(tmp_path, name="s"):
    store = ContentStore("artifactforge::test", str(tmp_path / "content"))
    return build_macos_scene(store, skey=KEY, profile=macos_profile(),
                             scene_dir=str(tmp_path / name / "scene"),
                             staging_dir=str(tmp_path / name / "staging"))


def _q(d, name, sql):
    con = sqlite3.connect(os.path.join(d, name))
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def test_the_subject_needs_two_databases_to_identify(tmp_path):
    s = _scene(tmp_path)
    granted = {r[0] for r in _q(s.directory, "TCC.db",
                                "SELECT client FROM access WHERE auth_value = 2")}
    used = {r[0] for r in _q(s.directory, "knowledgeC.db",
                             "SELECT ZVALUESTRING FROM ZOBJECT "
                             "WHERE ZSTREAMNAME = '/app/inFocus'")}
    assert len(granted) >= 2, "one grant makes the question a lookup"
    assert len(used) >= 2, "one usage record makes the question a lookup"
    assert sorted(granted & used) == [s.join["subject"]["bundle_id"]]


def test_tcc_records_refusals_as_well_as_grants(tmp_path):
    s = _scene(tmp_path)
    rows = _q(s.directory, "TCC.db", "SELECT client, auth_value FROM access")
    assert {a for _, a in rows} == {0, 2}, "a database of only grants is not evidence"


def test_five_quarantine_uuids_form_a_bijection_to_opaque_urls(tmp_path):
    s = _scene(tmp_path)
    rows = _q(s.directory, "QuarantineEventsV2",
              "SELECT LSQuarantineEventIdentifier, LSQuarantineDataURLString, "
              "LSQuarantineAgentName, LSQuarantineTimeStamp FROM LSQuarantineEvent")
    assert len(rows) == 5
    assert len({row[0] for row in rows}) == 5
    assert len({row[1] for row in rows}) == 5
    assert len({row[2] for row in rows}) == 1
    assert len({row[3] for row in rows}) == 1
    by_uuid = {row[0]: row for row in rows}

    relations = s.join["benchmark_relations"]
    assert len(relations) == 5
    xattr_agents = set()
    xattr_times = set()
    for relation in relations:
        relative_path = relation["selector"]["xattr_relative_path"]
        with open(os.path.join(s.directory, relative_path), encoding="ascii") as file:
            _flags, encoded_time, agent, uuid = file.read().strip().split(";")
        xattr_agents.add(agent)
        xattr_times.add(encoded_time)
        assert uuid == relation["link_value"]
        row = by_uuid[uuid]
        assert row[1] == relation["expected"]
        assert row[2] == agent
        assert relation["candidate"].lower() not in row[1].lower()
    assert len(xattr_agents) == len(xattr_times) == 1


def test_launch_agent_persistence(tmp_path):
    s = _scene(tmp_path)
    subject = s.join["subject"]
    plists = sorted(f for f in os.listdir(s.directory) if f.endswith(".plist"))
    assert len(plists) >= 3, "one LaunchAgent makes persistence a lookup"
    with open(os.path.join(s.directory, f"{subject['bundle_id']}.plist"), "rb") as f:
        pl = plistlib.load(f)
    assert pl["Label"] == subject["bundle_id"]
    assert pl["ProgramArguments"][0] == subject["app_path"]
    assert pl["RunAtLoad"] is True


def test_a_persisted_app_without_a_grant_is_present_as_a_decoy(tmp_path):
    """Persistence alone must not identify the subject, or the TCC/knowledgeC join is
    decorative."""
    s = _scene(tmp_path)
    decoy = s.join["decoys"]["persisted_only"]
    assert os.path.exists(os.path.join(s.directory, f"{decoy}.plist"))
    granted = {r[0] for r in _q(s.directory, "TCC.db",
                                "SELECT client FROM access WHERE auth_value = 2")}
    assert decoy not in granted


def test_only_the_allowlisted_files_are_served(tmp_path):
    s = _scene(tmp_path)
    assert sorted(os.listdir(s.directory)) == s.artifacts
    assert not [f for f in s.artifacts if "MANIFEST" in f.upper()]


def test_two_clock_determinism(tmp_path):
    a, b = _scene(tmp_path, "a"), _scene(tmp_path, "b")
    assert a.artifacts == b.artifacts
    for name in a.artifacts:
        with open(os.path.join(a.directory, name), "rb") as fa, \
             open(os.path.join(b.directory, name), "rb") as fb:
            assert fa.read() == fb.read(), name
