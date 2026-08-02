# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Deterministic macOS forensic artifacts — the gap EvidenceForge structurally can't fill.

All are loose files a responder can inspect directly: SQLite databases (knowledgeC / TCC /
QuarantineEventsV2), a serialized com.apple.quarantine xattr value, and a LaunchAgent plist.
They are built deterministically (pinned timestamps and rowids, no wall clock). Gate 1 pairs
sqlite3/plistlib with bounded first-party raw readers, requires type-exact consensus, then
checks exact artifact profiles; the xattr sidecar is join data rather than a parser-gated
format. Its UUID equals the
QuarantineEventsV2 row identifier — the macOS cross-artifact join.

SQLite files embed the writing library's version in their header; two builds with the same
sqlite3 are byte-identical (two-clock gate), but cross-version reproducibility is a disclosed
tell. No real extended attributes are set on the host — the xattr value is emitted as data.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import os
from itertools import islice
from pathlib import PurePosixPath
import plistlib
import re
import sqlite3
import stat
import struct
import tempfile
import unicodedata
from urllib.parse import urlsplit

from artifactforge.disclosure import MARKER, NOTICE, RESERVED_NAME


_PAGE_SIZE = 4096
_MAX_PROFILE_ROWS = 8
_UUID = re.compile(
    r"[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}"
)
_QUARANTINE_VALUE = re.compile(
    rf"(?P<flags>0181);(?P<timestamp>[0-9a-f]{{8}});"
    rf"(?P<agent>[A-Za-z0-9][A-Za-z0-9 ._-]{{0,63}});(?P<uuid>{_UUID.pattern})"
)
_LAUNCH_LABEL = re.compile(
    r"[a-z][a-z0-9-]{0,62}(?:\.[a-z0-9][a-z0-9-]{0,62}){2,}"
)


@dataclass(frozen=True)
class QuarantineValue:
    flags: str
    timestamp_unix: int
    agent: str
    event_uuid: str


def parse_quarantine_xattr(data: bytes) -> QuarantineValue:
    """Parse the exact serialized ``com.apple.quarantine`` benchmark profile.

    The loose sidecar is an exact byte representation of an xattr value: no BOM, newline,
    padding, permissive whitespace, lowercase UUID, or extra field is accepted.
    """
    if type(data) is not bytes:
        raise ValueError("quarantine xattr value must be bytes")
    try:
        text = data.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("quarantine xattr value must be strict ASCII") from exc
    match = _QUARANTINE_VALUE.fullmatch(text)
    if match is None:
        raise ValueError("quarantine xattr value is outside the exact four-field profile")
    return QuarantineValue(
        match.group("flags"),
        int(match.group("timestamp"), 16),
        match.group("agent"),
        match.group("uuid"),
    )


def _rows(value, *, where: str, width: int) -> tuple[tuple, ...]:
    """Materialise a bounded row iterable once and validate its outer shape."""
    if isinstance(value, (str, bytes, bytearray, dict)):
        raise ValueError(f"{where} rows must be an iterable of {width}-item rows")
    try:
        materialised = tuple(islice(iter(value), _MAX_PROFILE_ROWS + 1))
    except TypeError as exc:
        raise ValueError(f"{where} rows must be iterable") from exc
    if not 1 <= len(materialised) <= _MAX_PROFILE_ROWS:
        raise ValueError(
            f"{where} requires 1..{_MAX_PROFILE_ROWS} rows for the leaf-page profile"
        )
    for index, row in enumerate(materialised):
        if not isinstance(row, (tuple, list)) or len(row) != width:
            raise ValueError(f"{where} row {index} must contain exactly {width} values")
    return tuple(tuple(row) for row in materialised)


def _text(value, *, where: str, max_bytes: int, ascii_only: bool = True) -> str:
    if type(value) is not str:
        raise ValueError(f"{where} must be text")
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError(f"{where} must be Unicode NFC")
    if not value or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError(f"{where} must be non-empty and contain no control characters")
    try:
        encoded = value.encode("ascii" if ascii_only else "utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        kind = "ASCII" if ascii_only else "UTF-8"
        raise ValueError(f"{where} must be {kind} text") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"{where} exceeds the {max_bytes}-byte profile limit")
    return value


def _integer(value, *, where: str) -> int:
    if type(value) is not int or not -(1 << 63) <= value < 1 << 63:
        raise ValueError(f"{where} must be a signed 64-bit integer (not bool)")
    return value


def _finite_number(value, *, where: str) -> float:
    if type(value) not in (int, float):
        raise ValueError(f"{where} must be an integer or finite float (not bool)")
    result = float(value)
    if not math.isfinite(result) or abs(result) >= 2**53:
        raise ValueError(f"{where} must be finite and exactly representable in profile range")
    return result


def _https_url(value: str, *, where: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError(f"{where} must be an HTTPS URL without credentials or fragment")
    return value


def _assert_sqlite_leaf_profile(data: bytes, expected_page_types: tuple[int, ...]) -> bytes:
    """Never return a database outside the subset Gate 1's raw reader can inspect."""
    expected_size = len(expected_page_types) * _PAGE_SIZE
    if len(data) != expected_size:
        raise ValueError(
            f"SQLite profile exceeded its fixed leaf-page layout: {len(data)} != {expected_size}"
        )
    if data[:16] != b"SQLite format 3\x00" or data[16:18] != b"\x10\x00":
        raise ValueError("SQLite writer produced an unsupported header/page size")
    if int.from_bytes(data[28:32], "big") != len(expected_page_types):
        raise ValueError("SQLite writer page count does not match the emitted bytes")
    if any(data[32:40]) or any(data[52:56]) or any(data[64:68]):
        raise ValueError("SQLite writer emitted freelist or auto-vacuum pages")
    observed = tuple(
        data[(index * _PAGE_SIZE) + (100 if index == 0 else 0)]
        for index in range(len(expected_page_types))
    )
    if observed != expected_page_types:
        raise ValueError(
            f"SQLite writer left the supported leaf-root layout: {observed!r}"
        )
    for index in range(len(expected_page_types)):
        page = data[index * _PAGE_SIZE:(index + 1) * _PAGE_SIZE]
        header = 100 if index == 0 else 0
        first_freeblock = int.from_bytes(page[header + 1:header + 3], "big")
        cell_count = int.from_bytes(page[header + 3:header + 5], "big")
        content_start = int.from_bytes(page[header + 5:header + 7], "big")
        pointer_end = header + 8 + (2 * cell_count)
        if not pointer_end <= content_start <= _PAGE_SIZE:
            raise ValueError("SQLite writer produced overlapping pointer/content regions")
        if any(page[pointer_end:content_start]):
            raise ValueError("SQLite writer produced non-zero unallocated page bytes")
        seen = set()
        offset = first_freeblock
        while offset:
            if offset in seen or not content_start <= offset <= _PAGE_SIZE - 4:
                raise ValueError("SQLite writer produced an invalid freeblock chain")
            seen.add(offset)
            next_offset = int.from_bytes(page[offset:offset + 2], "big")
            size = int.from_bytes(page[offset + 2:offset + 4], "big")
            if size < 4 or offset + size > _PAGE_SIZE:
                raise ValueError("SQLite writer produced an invalid freeblock size")
            if any(page[offset + 4:offset + size]):
                raise ValueError("SQLite writer produced non-zero freeblock body bytes")
            offset = next_offset
    return data


def _mark(con) -> None:
    """A reserved table naming ArtifactForge, so the file discloses itself.

    Real forensic queries never touch it and `strings` cannot miss it. A schema a genuine
    macOS database would not have is exactly the point: this must not be mistakable for one.
    """
    con.execute(f"CREATE TABLE {RESERVED_NAME} (marker TEXT, notice TEXT)")
    con.execute(f"INSERT INTO {RESERVED_NAME} VALUES (?, ?)", (MARKER, NOTICE))


def _sqlite_bytes(build, *, expected_page_types: tuple[int, ...]) -> bytes:
    # sqlite3 needs a pathname. Keep an exclusive inode open inside a private directory while
    # SQLite opens that same name. If the name is swapped before SQLite opens it, our retained
    # inode stays empty and validation fails; if it is swapped later, we still read the inode
    # SQLite wrote. Never unlink and then reopen an attacker-replaceable name.
    with tempfile.TemporaryDirectory(prefix="artifactforge-sqlite-") as directory:
        fd, path = tempfile.mkstemp(prefix="artifact-", suffix=".db", dir=directory)
        try:
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size != 0
            ):
                raise ValueError("SQLite writer output is not one private regular inode")
            con = sqlite3.connect(path)
            try:
                con.execute("PRAGMA page_size=4096")
                con.execute("PRAGMA legacy_file_format=ON")
                con.execute("PRAGMA journal_mode=DELETE")
                build(con)
                _mark(con)
                con.commit()
            finally:
                con.close()

            expected_size = len(expected_page_types) * _PAGE_SIZE
            written = os.fstat(fd)
            if (
                (written.st_dev, written.st_ino) != (before.st_dev, before.st_ino)
                or written.st_size != expected_size
            ):
                raise ValueError(
                    f"SQLite writer output size {written.st_size} != {expected_size}"
                )
            os.lseek(fd, 0, os.SEEK_SET)
            chunks = []
            remaining = expected_size + 1
            while remaining:
                chunk = os.read(fd, min(remaining, 64 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            after = os.fstat(fd)
            if (
                (written.st_dev, written.st_ino, written.st_size, written.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            ):
                raise ValueError("SQLite writer output changed while it was being read")
        finally:
            os.close(fd)
        return _assert_sqlite_leaf_profile(data, expected_page_types)


def build_knowledgec(entries) -> bytes:
    """/private/var/db/CoreDuet/Knowledge/knowledgeC.db — app-in-focus usage.

    `entries` is a sequence of (bundle_id, start_mac, end_mac). A real knowledgeC holds
    weeks of every app a user touched, so "which app was used" is only a question when
    several were.
    """
    entries = _rows(entries, where="knowledgeC", width=3)
    validated = []
    bundles = set()
    for index, (bundle_id, start_mac, end_mac) in enumerate(entries):
        bundle_id = _text(
            bundle_id, where=f"knowledgeC row {index} bundle_id", max_bytes=128
        )
        start = _finite_number(start_mac, where=f"knowledgeC row {index} start")
        end = _finite_number(end_mac, where=f"knowledgeC row {index} end")
        if end <= start:
            raise ValueError(f"knowledgeC row {index} end must be after start")
        if bundle_id in bundles:
            raise ValueError(f"knowledgeC bundle_id is duplicated: {bundle_id!r}")
        bundles.add(bundle_id)
        validated.append((bundle_id, start, end))

    def build(con):
        con.execute(
            "CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME TEXT, "
            "ZVALUESTRING TEXT, ZSTARTDATE REAL, ZENDDATE REAL)")
        for i, (bundle_id, start_mac, end_mac) in enumerate(validated, start=1):
            con.execute("INSERT INTO ZOBJECT VALUES (?, '/app/inFocus', ?, ?, ?)",
                        (i, bundle_id, float(start_mac), float(end_mac)))
    return _sqlite_bytes(build, expected_page_types=(0x0D, 0x0D, 0x0D))


def build_tcc(rows) -> bytes:
    """~/Library/Application Support/com.apple.TCC/TCC.db — permission grants and refusals.

    `rows` is a sequence of (client, service, auth_value, last_modified_unix).

    Note the units: `access.last_modified` is a **Unix** timestamp, unlike almost every other
    macOS forensic column, which uses Mac absolute time (seconds since 2001-01-01). Getting
    that wrong shifts every TCC grant by 31 years, and an analyst converting the column with
    the usual macOS recipe would notice immediately.

    auth_value 2 is allowed, 0 is denied; a database containing only grants would make
    "which app was allowed" a lookup rather than a question.
    """
    rows = _rows(rows, where="TCC", width=4)
    validated = []
    clients = set()
    for index, (client, service, auth_value, last_modified) in enumerate(rows):
        client = _text(client, where=f"TCC row {index} client", max_bytes=128)
        service = _text(service, where=f"TCC row {index} service", max_bytes=96)
        auth_value = _integer(auth_value, where=f"TCC row {index} auth_value")
        if auth_value not in {0, 2}:
            raise ValueError(f"TCC row {index} auth_value must be 0 or 2")
        last_modified = _integer(
            last_modified, where=f"TCC row {index} last_modified"
        )
        if last_modified <= 0:
            raise ValueError(f"TCC row {index} last_modified must be positive Unix time")
        if client in clients:
            raise ValueError(f"TCC client is duplicated: {client!r}")
        clients.add(client)
        validated.append((client, service, auth_value, last_modified))

    def build(con):
        con.execute(
            "CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, "
            "auth_value INTEGER, auth_reason INTEGER, last_modified INTEGER)")
        for client, service, auth_value, last_modified in validated:
            con.execute("INSERT INTO access VALUES (?, ?, 0, ?, 3, ?)",
                        (service, client, auth_value, last_modified))
    return _sqlite_bytes(build, expected_page_types=(0x0D, 0x0D, 0x0D))


def build_quarantine_events(events) -> bytes:
    """com.apple.LaunchServices.QuarantineEventsV2 — where each download came from.

    `events` is a sequence of (uuid, agent, data_url, origin_url, timestamp_mac).
    LSQuarantineEventIdentifier equals the file's com.apple.quarantine xattr UUID, which is
    the join: the database says where things came from, the xattr says which thing.
    """
    events = _rows(events, where="QuarantineEventsV2", width=5)
    validated = []
    identifiers = set()
    for index, (uuid, agent, data_url, origin_url, timestamp_mac) in enumerate(events):
        uuid = _text(uuid, where=f"quarantine row {index} UUID", max_bytes=36)
        if not _UUID.fullmatch(uuid):
            raise ValueError(f"quarantine row {index} UUID is not canonical RFC 4122 v4")
        if uuid in identifiers:
            raise ValueError(f"quarantine UUID is duplicated: {uuid!r}")
        identifiers.add(uuid)
        agent = _text(agent, where=f"quarantine row {index} agent", max_bytes=64)
        data_url = _text(
            data_url, where=f"quarantine row {index} data URL", max_bytes=256
        )
        _https_url(data_url, where=f"quarantine row {index} data URL")
        origin_url = _text(
            origin_url, where=f"quarantine row {index} origin URL", max_bytes=256
        )
        _https_url(origin_url, where=f"quarantine row {index} origin URL")
        timestamp = _finite_number(
            timestamp_mac, where=f"quarantine row {index} timestamp"
        )
        if timestamp < 0:
            raise ValueError(f"quarantine row {index} timestamp must be non-negative Mac time")
        validated.append((uuid, agent, data_url, origin_url, timestamp))

    def build(con):
        con.execute(
            "CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT PRIMARY KEY, "
            "LSQuarantineTimeStamp REAL, LSQuarantineAgentName TEXT, "
            "LSQuarantineDataURLString TEXT, LSQuarantineOriginURLString TEXT)")
        for uuid, agent, data_url, origin_url, timestamp_mac in validated:
            con.execute("INSERT INTO LSQuarantineEvent VALUES (?, ?, ?, ?, ?)",
                        (uuid, float(timestamp_mac), agent, data_url, origin_url))
    return _sqlite_bytes(
        build, expected_page_types=(0x0D, 0x0D, 0x0A, 0x0D)
    )


def quarantine_xattr(uuid: str, agent: str, timestamp_unix: int, flags: str = "0181") -> str:
    """The com.apple.quarantine xattr value: flags;hex-time;agent;UUID (UUID joins the DB row)."""
    value = f"{flags};{timestamp_unix:08x};{agent};{uuid}"
    parse_quarantine_xattr(value.encode("ascii", errors="strict"))
    return value


def build_launch_agent(label: str, program_path: str, run_at_load: bool = True) -> bytes:
    """~/Library/LaunchAgents/<label>.plist — macOS persistence (binary plist, plistlib-readable)."""
    label = _text(label, where="LaunchAgent label", max_bytes=128)
    if not _LAUNCH_LABEL.fullmatch(label):
        raise ValueError("LaunchAgent label must be a lowercase reverse-DNS identifier")
    program_path = _text(program_path, where="LaunchAgent program path", max_bytes=512)
    path = PurePosixPath(program_path)
    if (
        not program_path.startswith("/")
        or program_path == "/"
        or program_path.startswith("//")
        or "\\" in program_path
        or path.as_posix() != program_path
        or any(part in {"", ".", ".."} for part in program_path.split("/")[1:])
    ):
        raise ValueError("LaunchAgent program path must be an absolute normal POSIX path")
    if run_at_load is not True:
        raise ValueError("LaunchAgent run_at_load must be true for the persistence profile")
    plist = {
        "Label": label,
        "ProgramArguments": [program_path],
        "RunAtLoad": run_at_load,
        "StartInterval": 3600,
        # launchd ignores keys it does not know, so the disclosure rides along harmlessly
        # and survives the file being copied out of its bundle.
        RESERVED_NAME: MARKER,
        f"{RESERVED_NAME}_notice": NOTICE,
    }
    data = plistlib.dumps(plist, fmt=plistlib.FMT_BINARY, sort_keys=True)
    if len(data) >= 65536 or data[:8] != b"bplist00":
        raise ValueError("LaunchAgent left the bounded binary-plist profile")
    offset_size, reference_size, object_count, top_object, _table_offset = struct.unpack(
        ">6xBBQQQ", data[-32:]
    )
    if (
        offset_size not in {1, 2}
        or reference_size != 1
        or not 1 <= object_count <= 14
        or top_object != 0
    ):
        raise ValueError("LaunchAgent left the bounded binary-plist profile")
    return data
