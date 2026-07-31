"""macOS breadth proof: a coherent macOS crime scene EvidenceForge cannot produce.

One app identity surfaces as: a QuarantineEventsV2 download record, a matching
com.apple.quarantine xattr (UUID join), a granted TCC permission, a knowledgeC usage event,
and a LaunchAgent persistence plist. Each artifact is validated by a real reader (sqlite3
with the canonical forensic queries; plistlib), driven entirely by a HostProfile.
"""
import plistlib
import sqlite3

from artifactforge.profile import macos_profile
from artifactforge.scenario import build_macos_crime_scene

APP = dict(bundle_id="com.acme.updater",
           app_path="/Users/v/Library/Application Support/Updater/updater",
           download_url="https://cdn.evil.example/update.dmg",
           origin_url="https://evil.example/download", agent="Safari")


def _scene(tmp_path):
    return build_macos_crime_scene(macos_profile(username="v"), out_dir=str(tmp_path / "mac"), **APP)


def _query(path, sql):
    con = sqlite3.connect(path)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def test_quarantine_download_record(tmp_path):
    s = _scene(tmp_path)
    rows = _query(s.artifacts["QuarantineEventsV2"],
                  "SELECT LSQuarantineEventIdentifier, LSQuarantineDataURLString FROM LSQuarantineEvent")
    assert rows[0][0] == s.join["quarantine_uuid"]
    assert rows[0][1] == APP["download_url"]


def test_quarantine_xattr_uuid_join(tmp_path):
    """The file's quarantine xattr UUID must equal the QuarantineEventsV2 row — the macOS join."""
    s = _scene(tmp_path)
    with open(s.artifacts["quarantine_xattr"]) as f:
        xattr = f.read()
    uuid_in_xattr = xattr.split(";")[-1]
    db_uuid = _query(s.artifacts["QuarantineEventsV2"],
                     "SELECT LSQuarantineEventIdentifier FROM LSQuarantineEvent")[0][0]
    assert uuid_in_xattr == db_uuid


def test_tcc_permission_granted(tmp_path):
    s = _scene(tmp_path)
    rows = _query(s.artifacts["TCC.db"],
                  "SELECT client, service, auth_value FROM access WHERE auth_value = 2")
    assert rows[0][0] == APP["bundle_id"]
    assert rows[0][1] == "kTCCServiceSystemPolicyAllFiles"


def test_knowledgec_app_usage(tmp_path):
    s = _scene(tmp_path)
    rows = _query(s.artifacts["knowledgeC.db"],
                  "SELECT ZVALUESTRING FROM ZOBJECT WHERE ZSTREAMNAME = '/app/inFocus'")
    assert rows[0][0] == APP["bundle_id"]


def test_launch_agent_persistence(tmp_path):
    s = _scene(tmp_path)
    with open(s.artifacts["com.acme.updater.plist"], "rb") as f:
        pl = plistlib.load(f)
    assert pl["Label"] == APP["bundle_id"]
    assert pl["ProgramArguments"][0] == APP["app_path"]
    assert pl["RunAtLoad"] is True


def test_two_clock_determinism(tmp_path):
    a = _scene(tmp_path / "a")
    b = _scene(tmp_path / "b")
    for kind in a.artifacts:
        assert open(a.artifacts[kind], "rb").read() == open(b.artifacts[kind], "rb").read()
