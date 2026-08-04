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

SQLite bytes are emitted by ArtifactForge's owned, leaf-only encoder rather than the host
SQLite library.  Header offset 96 is therefore the honest value zero: no SQLite library wrote
the file.  No real extended attributes are set on the host — the xattr value is emitted as
data and Fixture ABI v2 binds its eventual guest metadata separately from carrier metadata.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
from itertools import islice
from pathlib import PurePosixPath
import plistlib
import re
import struct
import unicodedata
from urllib.parse import urlsplit

from artifactforge.disclosure import MARKER, NOTICE, RESERVED_NAME
from artifactforge.artifacts.sqlite_owned import ColumnSpec, TableSpec, build_sqlite


_MAX_PROFILE_ROWS = 8
# This names a query-compatibility surface, not an Apple schema claim.  Version 1 is the
# smallest leaf-page subset that runs the macOS 11--14 APOLLO app-in-focus query and the
# macOS 11+ mac_apt TCC query current on 2026-08-03.  Expanding it is an ABI change because
# the CREATE SQL and page ownership are validated byte-for-byte by Gate 1.
SQLITE_CONSUMER_PROFILE = "macos-11-14-consumer-v1"
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
_KNOWLEDGEC_IDENTITY_DOMAIN_V2 = b"artifactforge/knowledgec/identity/v2\0"
_KNOWLEDGEC_METADATA_DOMAIN_V2 = b"artifactforge/knowledgec/metadata/v2\0"


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


def _marker_table() -> TableSpec:
    """A reserved, plainly synthetic table ignored by real forensic queries."""
    return TableSpec(
        RESERVED_NAME,
        (ColumnSpec("marker", "TEXT"), ColumnSpec("notice", "TEXT")),
        ((MARKER, NOTICE),),
    )


def _knowledgec_uuid_v2(identity_seed: bytes, rowid: int, bundle_id: str) -> str:
    digest = bytearray(
        hashlib.sha256(
            _KNOWLEDGEC_IDENTITY_DOMAIN_V2
            + identity_seed
            + b"\0"
            + str(rowid).encode("ascii")
            + b"\0"
            + bundle_id.encode("ascii")
        ).digest()[:16]
    )
    digest[6] = (digest[6] & 0x0F) | 0x40
    digest[8] = (digest[8] & 0x3F) | 0x80
    value = digest.hex().upper()
    return (
        f"{value[:8]}-{value[8:12]}-{value[12:16]}-"
        f"{value[16:20]}-{value[20:32]}"
    )


def build_knowledgec(entries, *, identity_seed: bytes | None = None) -> bytes:
    """/private/var/db/CoreDuet/Knowledge/knowledgeC.db — app-in-focus usage.

    `entries` is a sequence of (bundle_id, start_mac, end_mac). A real knowledgeC holds
    weeks of every app a user touched, so "which app was used" is only a question when
    several were.

    The emitted schema is :data:`SQLITE_CONSUMER_PROFILE`, a deliberately bounded
    query-compatible subset rather than a captured CoreData schema.  It carries every table,
    join key and selected column used by APOLLO's macOS 11--14 app-in-focus query.  Gate 1
    checks the foreign keys and derived fields as well as parser agreement; this does not
    assert OS-version fidelity for unmodelled knowledgeC tables or columns.
    """
    entries = _rows(entries, where="knowledgeC", width=3)
    validated = []
    for index, (bundle_id, start_mac, end_mac) in enumerate(entries):
        bundle_id = _text(
            bundle_id, where=f"knowledgeC row {index} bundle_id", max_bytes=128
        )
        start = _finite_number(start_mac, where=f"knowledgeC row {index} start")
        end = _finite_number(end_mac, where=f"knowledgeC row {index} end")
        if end <= start:
            raise ValueError(f"knowledgeC row {index} end must be after start")
        validated.append((bundle_id, start, end))

    if identity_seed is not None and (
        type(identity_seed) is not bytes or len(identity_seed) != 32
    ):
        raise ValueError("knowledgeC identity_seed must be exactly 32 bytes or None")

    object_rows = []
    metadata_rows = []
    for i, (bundle_id, start_mac, end_mac) in enumerate(validated, start=1):
        # 1970-01-01 was Thursday (5 in knowledgeC's Sunday=1 convention).
        unix_day = math.floor((start_mac + 978_307_200) / 86_400)
        day_of_week = ((unix_day + 4) % 7) + 1
        if identity_seed is None:
            uuid = f"00000000-0000-4000-8000-{i:012X}"
            metadata_hash = hashlib.sha256(
                b"artifactforge::knowledgec-metadata\x00" + bundle_id.encode("ascii")
            ).hexdigest()
        else:
            uuid = _knowledgec_uuid_v2(identity_seed, i, bundle_id)
            metadata_hash = hashlib.sha256(
                _KNOWLEDGEC_METADATA_DOMAIN_V2
                + uuid.encode("ascii")
                + b"\0"
                + bundle_id.encode("ascii")
            ).hexdigest()
        metadata_rows.append((i, 0, "UNUSED", "UNUSED", metadata_hash))
        object_rows.append(
            (
                i,
                "/app/inFocus",
                bundle_id,
                float(start_mac),
                float(end_mac),
                day_of_week,
                0,
                float(start_mac),
                uuid,
                i,
                1,
            )
        )

    return build_sqlite(
        (
            TableSpec(
                "ZOBJECT",
                (
                    ColumnSpec("Z_PK", "INTEGER", primary_key=True),
                    ColumnSpec("ZSTREAMNAME", "TEXT"),
                    ColumnSpec("ZVALUESTRING", "TEXT"),
                    ColumnSpec("ZSTARTDATE", "REAL"),
                    ColumnSpec("ZENDDATE", "REAL"),
                    ColumnSpec("ZSTARTDAYOFWEEK", "INTEGER"),
                    ColumnSpec("ZSECONDSFROMGMT", "INTEGER"),
                    ColumnSpec("ZCREATIONDATE", "REAL"),
                    ColumnSpec("ZUUID", "TEXT"),
                    ColumnSpec("ZSTRUCTUREDMETADATA", "INTEGER"),
                    ColumnSpec("ZSOURCE", "INTEGER"),
                ),
                tuple(object_rows),
            ),
            TableSpec(
                "ZSTRUCTUREDMETADATA",
                (
                    ColumnSpec("Z_PK", "INTEGER", primary_key=True),
                    ColumnSpec(
                        "Z_DKAPPLICATIONMETADATAKEY__LAUNCHREASON", "INTEGER"
                    ),
                    ColumnSpec(
                        "Z_DKAPPLICATIONMETADATAKEY__EXTENSIONCONTAININGBUNDLEIDENTIFIER",
                        "TEXT",
                    ),
                    ColumnSpec(
                        "Z_DKAPPLICATIONMETADATAKEY__EXTENSIONHOSTIDENTIFIER", "TEXT"
                    ),
                    ColumnSpec("ZMETADATAHASH", "TEXT"),
                ),
                tuple(metadata_rows),
            ),
            TableSpec(
                "ZSOURCE",
                (ColumnSpec("Z_PK", "INTEGER", primary_key=True),),
                ((1,),),
            ),
            _marker_table(),
        )
    )


def build_tcc(rows) -> bytes:
    """~/Library/Application Support/com.apple.TCC/TCC.db — permission grants and refusals.

    `rows` is a sequence of (client, service, auth_value, last_modified_unix).

    Note the units: `access.last_modified` is a **Unix** timestamp, unlike almost every other
    macOS forensic column, which uses Mac absolute time (seconds since 2001-01-01). Getting
    that wrong shifts every TCC grant by 31 years, and an analyst converting the column with
    the usual macOS recipe would notice immediately.

    auth_value 2 is allowed, 0 is denied; a database containing only grants would make
    "which app was allowed" a lookup rather than a question.

    The emitted schema is :data:`SQLITE_CONSUMER_PROFILE`, not a complete captured TCC
    schema.  It includes the macOS 11+ fields selected by mac_apt, including
    ``indirect_object_identifier``; unmodelled code-signing blobs and policy tables are
    outside this profile and no OS-version-fidelity claim follows from query success.
    """
    rows = _rows(rows, where="TCC", width=4)
    validated = []
    identities = set()
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
        identity = service, client
        if identity in identities:
            raise ValueError(f"TCC service/client identity is duplicated: {identity!r}")
        identities.add(identity)
        validated.append((client, service, auth_value, last_modified))

    return build_sqlite(
        (
            TableSpec(
                "access",
                (
                    ColumnSpec("service", "TEXT"),
                    ColumnSpec("client", "TEXT"),
                    ColumnSpec("client_type", "INTEGER"),
                    ColumnSpec("auth_value", "INTEGER"),
                    ColumnSpec("auth_reason", "INTEGER"),
                    ColumnSpec("indirect_object_identifier", "TEXT"),
                    ColumnSpec("last_modified", "INTEGER"),
                ),
                tuple(
                    (service, client, 0, auth_value, 3, "UNUSED", last_modified)
                    for client, service, auth_value, last_modified in validated
                ),
            ),
            _marker_table(),
        )
    )


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

    return build_sqlite(
        (
            TableSpec(
                "LSQuarantineEvent",
                (
                    ColumnSpec(
                        "LSQuarantineEventIdentifier", "TEXT", primary_key=True
                    ),
                    ColumnSpec("LSQuarantineTimeStamp", "REAL"),
                    ColumnSpec("LSQuarantineAgentName", "TEXT"),
                    ColumnSpec("LSQuarantineDataURLString", "TEXT"),
                    ColumnSpec("LSQuarantineOriginURLString", "TEXT"),
                ),
                tuple(
                    (uuid, float(timestamp_mac), agent, data_url, origin_url)
                    for uuid, agent, data_url, origin_url, timestamp_mac in validated
                ),
            ),
            _marker_table(),
        )
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
