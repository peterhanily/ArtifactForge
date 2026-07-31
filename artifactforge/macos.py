"""Deterministic macOS forensic artifacts — the gap EvidenceForge structurally can't fill.

All are loose files a responder's tools read directly: SQLite databases (knowledgeC / TCC /
QuarantineEventsV2), the com.apple.quarantine xattr value, and a LaunchAgent plist. Each is
built deterministically (pinned timestamps and rowids, no wall clock) and validated by a real
reader (sqlite3 with the canonical forensic queries; plistlib). The quarantine xattr UUID
equals the QuarantineEventsV2 row identifier — the macOS cross-artifact join.

SQLite files embed the writing library's version in their header; two builds with the same
sqlite3 are byte-identical (two-clock gate), but cross-version reproducibility is a disclosed
tell. No real extended attributes are set on the host — the xattr value is emitted as data.
"""
from __future__ import annotations

import os
import plistlib
import sqlite3
import tempfile


def _sqlite_bytes(build) -> bytes:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.remove(path)
    try:
        con = sqlite3.connect(path)
        con.execute("PRAGMA page_size=4096")
        con.execute("PRAGMA legacy_file_format=ON")
        con.execute("PRAGMA journal_mode=DELETE")
        build(con)
        con.commit()
        con.close()
        with open(path, "rb") as f:
            return f.read()
    finally:
        if os.path.exists(path):
            os.remove(path)


def build_knowledgec(bundle_id: str, start_mac: int, end_mac: int) -> bytes:
    """/private/var/db/CoreDuet/Knowledge/knowledgeC.db — app-in-focus usage (APOLLO-readable)."""
    def build(con):
        con.execute(
            "CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME TEXT, "
            "ZVALUESTRING TEXT, ZSTARTDATE REAL, ZENDDATE REAL)")
        con.execute("INSERT INTO ZOBJECT VALUES (1, '/app/inFocus', ?, ?, ?)",
                    (bundle_id, float(start_mac), float(end_mac)))
    return _sqlite_bytes(build)


def build_tcc(bundle_id: str, service: str, last_modified_mac: int) -> bytes:
    """~/Library/Application Support/com.apple.TCC/TCC.db — a granted sensitive permission."""
    def build(con):
        con.execute(
            "CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, "
            "auth_value INTEGER, auth_reason INTEGER, last_modified INTEGER)")
        con.execute("INSERT INTO access VALUES (?, ?, 0, 2, 3, ?)",
                    (service, bundle_id, last_modified_mac))  # auth_value 2 = allowed
    return _sqlite_bytes(build)


def build_quarantine_events(uuid: str, agent: str, data_url: str, origin_url: str,
                            timestamp_mac: int) -> bytes:
    """com.apple.LaunchServices.QuarantineEventsV2 — where a download came from.

    LSQuarantineEventIdentifier equals the file's com.apple.quarantine xattr UUID.
    """
    def build(con):
        con.execute(
            "CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT PRIMARY KEY, "
            "LSQuarantineTimeStamp REAL, LSQuarantineAgentName TEXT, "
            "LSQuarantineDataURLString TEXT, LSQuarantineOriginURLString TEXT)")
        con.execute("INSERT INTO LSQuarantineEvent VALUES (?, ?, ?, ?, ?)",
                    (uuid, float(timestamp_mac), agent, data_url, origin_url))
    return _sqlite_bytes(build)


def quarantine_xattr(uuid: str, agent: str, timestamp_unix: int, flags: str = "0181") -> str:
    """The com.apple.quarantine xattr value: flags;hex-time;agent;UUID (UUID joins the DB row)."""
    return f"{flags};{timestamp_unix:08x};{agent};{uuid}"


def build_launch_agent(label: str, program_path: str, run_at_load: bool = True) -> bytes:
    """~/Library/LaunchAgents/<label>.plist — macOS persistence (binary plist, plistlib-readable)."""
    plist = {
        "Label": label,
        "ProgramArguments": [program_path],
        "RunAtLoad": run_at_load,
        "StartInterval": 3600,
    }
    return plistlib.dumps(plist, fmt=plistlib.FMT_BINARY, sort_keys=True)
