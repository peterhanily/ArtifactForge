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


def build_knowledgec(entries) -> bytes:
    """/private/var/db/CoreDuet/Knowledge/knowledgeC.db — app-in-focus usage.

    `entries` is a sequence of (bundle_id, start_mac, end_mac). A real knowledgeC holds
    weeks of every app a user touched, so "which app was used" is only a question when
    several were.
    """
    def build(con):
        con.execute(
            "CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME TEXT, "
            "ZVALUESTRING TEXT, ZSTARTDATE REAL, ZENDDATE REAL)")
        for i, (bundle_id, start_mac, end_mac) in enumerate(entries, start=1):
            con.execute("INSERT INTO ZOBJECT VALUES (?, '/app/inFocus', ?, ?, ?)",
                        (i, bundle_id, float(start_mac), float(end_mac)))
    return _sqlite_bytes(build)


def build_tcc(rows) -> bytes:
    """~/Library/Application Support/com.apple.TCC/TCC.db — permission grants and refusals.

    `rows` is a sequence of (client, service, auth_value, last_modified_mac).
    auth_value 2 is allowed, 0 is denied; a database containing only grants would make
    "which app was allowed" a lookup rather than a question.
    """
    def build(con):
        con.execute(
            "CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, "
            "auth_value INTEGER, auth_reason INTEGER, last_modified INTEGER)")
        for client, service, auth_value, last_modified in rows:
            con.execute("INSERT INTO access VALUES (?, ?, 0, ?, 3, ?)",
                        (service, client, auth_value, last_modified))
    return _sqlite_bytes(build)


def build_quarantine_events(events) -> bytes:
    """com.apple.LaunchServices.QuarantineEventsV2 — where each download came from.

    `events` is a sequence of (uuid, agent, data_url, origin_url, timestamp_mac).
    LSQuarantineEventIdentifier equals the file's com.apple.quarantine xattr UUID, which is
    the join: the database says where things came from, the xattr says which thing.
    """
    def build(con):
        con.execute(
            "CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT PRIMARY KEY, "
            "LSQuarantineTimeStamp REAL, LSQuarantineAgentName TEXT, "
            "LSQuarantineDataURLString TEXT, LSQuarantineOriginURLString TEXT)")
        for uuid, agent, data_url, origin_url, timestamp_mac in events:
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
