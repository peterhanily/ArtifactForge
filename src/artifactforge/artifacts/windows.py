# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Deterministic Windows responder artifacts beyond PE, REGF and Prefetch.

The Chromium history writer intentionally implements a bounded download-query surface, not a
complete browser profile database.  Its column order follows Chromium's current
``DownloadDatabase::InitDownloadTable`` and ``downloads_url_chains`` definitions, while the
owned SQLite encoder keeps generation independent of the host SQLite library.  Common
responder queries can therefore recover target paths, source/referrer URLs, Windows-epoch
timestamps and the raw content SHA-256 without this module claiming that Chromium itself
created, migrated or can continue writing the database.

Primary format reference (retrieved 2026-08-03):
https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/history/core/browser/download_database.cc
"""
from __future__ import annotations

from dataclasses import dataclass
from itertools import islice
import hashlib
import re
from urllib.parse import urlsplit

from artifactforge.artifacts.sqlite_owned import ColumnSpec, TableSpec, build_sqlite
from artifactforge.disclosure import MARKER, NOTICE, RESERVED_NAME


CHROMIUM_DOWNLOAD_PROFILE = "chromium-completed-download-query-surface-v1"
WINDOWS_EPOCH_MICROSECONDS = 11_644_473_600_000_000

_MAX_DOWNLOAD_ROWS = 8
_MAX_PATH_UTF16_BYTES = 520
_MAX_URL_BYTES = 512
_MAX_DOWNLOAD_BYTES = 1 << 40
_WINDOWS_PATH = re.compile(
    r"[A-Z]:\\(?:[^\\/:*?\"<>|\x00-\x1f]+\\)*[^\\/:*?\"<>|\x00-\x1f]+"
)
_UUID_V4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_CONTENT_PATH = re.compile(
    r".+/sha256/(?P<sha256>[0-9a-f]{64})/(?P<basename>[^/]+)"
)
_GUID_DOMAIN = b"artifactforge/chromium-download-guid/v1\0"


@dataclass(frozen=True)
class ChromiumDownload:
    """One complete, bounded Chromium download observation.

    Times are Chromium/base::Time internal values: microseconds since 1601-01-01 UTC.  The
    SHA-256 is the digest of the downloaded default-stream bytes.  Current Chromium leaves
    the database ``hash`` BLOB empty when it persists a completed download, so ArtifactForge
    binds this digest into the reserved content-addressed source URL instead of pretending
    Chromium stored it in that field.
    """

    target_path: str
    source_url: str
    referrer_url: str
    sha256: bytes
    size: int
    start_time_windows_us: int
    end_time_windows_us: int
    opened: bool
    last_access_time_windows_us: int


def _bounded_text(value: object, *, where: str, max_bytes: int) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{where} must be non-empty text")
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{where} must be strict ASCII") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"{where} exceeds the {max_bytes}-byte profile limit")
    if any(byte < 0x20 or byte == 0x7F for byte in encoded):
        raise ValueError(f"{where} contains a control character")
    return value


def _windows_path(value: object, *, where: str) -> str:
    value = _bounded_text(value, where=where, max_bytes=_MAX_PATH_UTF16_BYTES // 2)
    if _WINDOWS_PATH.fullmatch(value) is None or len(value.encode("utf-16-le")) > (
        _MAX_PATH_UTF16_BYTES
    ):
        raise ValueError(f"{where} must be a bounded absolute normal Windows drive path")
    components = value[3:].split("\\")
    if any(component in {"", ".", ".."} or component.endswith((" ", ".")) for component in components):
        raise ValueError(f"{where} must be a bounded absolute normal Windows drive path")
    return value


def _reserved_https_url(value: object, *, where: str) -> str:
    value = _bounded_text(value, where=where, max_bytes=_MAX_URL_BYTES)
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    if (
        parsed.scheme != "https"
        or parsed.netloc != host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not host.endswith((".example", ".invalid", ".test"))
        or MARKER not in value
    ):
        raise ValueError(
            f"{where} must be a marked reserved HTTPS URL without credentials, port, or "
            "fragment"
        )
    return value


def _windows_microseconds(value: object, *, where: str) -> int:
    if type(value) is not int or not WINDOWS_EPOCH_MICROSECONDS <= value < (1 << 63):
        raise ValueError(f"{where} must be an exact positive signed-64 Windows timestamp")
    if value % 1_000_000:
        raise ValueError(f"{where} must be aligned to the whole-second causal profile")
    return value


def _download_guid(identity_seed: bytes, rowid: int, target_path: str, digest: bytes) -> str:
    value = bytearray(
        hashlib.sha256(
            _GUID_DOMAIN
            + identity_seed
            + rowid.to_bytes(4, "big")
            + target_path.encode("ascii")
            + b"\0"
            + digest
        ).digest()[:16]
    )
    value[6] = (value[6] & 0x0F) | 0x40
    value[8] = (value[8] & 0x3F) | 0x80
    text = value.hex()
    result = f"{text[:8]}-{text[8:12]}-{text[12:16]}-{text[16:20]}-{text[20:]}"
    assert _UUID_V4.fullmatch(result)
    return result


def _downloads(value: object) -> tuple[ChromiumDownload, ...]:
    if isinstance(value, (str, bytes, bytearray, dict)):
        raise ValueError("Chromium downloads must be an iterable of ChromiumDownload values")
    try:
        rows = tuple(islice(iter(value), _MAX_DOWNLOAD_ROWS + 1))  # type: ignore[arg-type]
    except TypeError as exc:
        raise ValueError(
            "Chromium downloads must be an iterable of ChromiumDownload values"
        ) from exc
    if not 1 <= len(rows) <= _MAX_DOWNLOAD_ROWS:
        raise ValueError(
            f"Chromium history requires 1..{_MAX_DOWNLOAD_ROWS} download rows"
        )
    if any(type(row) is not ChromiumDownload for row in rows):
        raise ValueError("every Chromium download row must be an exact ChromiumDownload")
    return rows  # type: ignore[return-value]


def _marker_table() -> TableSpec:
    return TableSpec(
        RESERVED_NAME,
        (ColumnSpec("marker", "TEXT"), ColumnSpec("notice", "TEXT")),
        ((MARKER, NOTICE),),
    )


def build_chromium_history(
    downloads: object, *, identity_seed: bytes
) -> bytes:
    """Build a deterministic Chromium download-history query surface.

    ``identity_seed`` supplies domain-separated deterministic v4 GUIDs.  It is not stored in
    the output and must be exactly 32 immutable bytes.  Input is materialised once through a
    nine-item probe so unbounded iterables fail before schema or page allocation.
    """
    if type(identity_seed) is not bytes or len(identity_seed) != 32:
        raise ValueError("Chromium history identity_seed must be exactly 32 bytes")
    rows = _downloads(downloads)
    prepared = []
    identities: set[tuple[str, bytes]] = set()
    for index, row in enumerate(rows, start=1):
        target_path = _windows_path(row.target_path, where=f"download {index} target_path")
        source_url = _reserved_https_url(
            row.source_url, where=f"download {index} source_url"
        )
        referrer_url = _reserved_https_url(
            row.referrer_url, where=f"download {index} referrer_url"
        )
        if type(row.sha256) is not bytes or len(row.sha256) != 32:
            raise ValueError(f"download {index} sha256 must be exactly 32 immutable bytes")
        source = urlsplit(source_url)
        content_identity = _CONTENT_PATH.fullmatch(source.path)
        target_basename = target_path.rsplit("\\", 1)[-1]
        if (
            content_identity is None
            or source.path.count("/sha256/") != 1
            or content_identity.group("sha256") != row.sha256.hex()
            or content_identity.group("basename").casefold() != target_basename.casefold()
        ):
            raise ValueError(
                f"download {index} source_url must bind the lowercase SHA-256 and target "
                "basename"
            )
        if type(row.size) is not int or not 1 <= row.size <= _MAX_DOWNLOAD_BYTES:
            raise ValueError(
                f"download {index} size must be an exact integer in 1..{_MAX_DOWNLOAD_BYTES}"
            )
        start = _windows_microseconds(
            row.start_time_windows_us, where=f"download {index} start_time"
        )
        end = _windows_microseconds(
            row.end_time_windows_us, where=f"download {index} end_time"
        )
        if end <= start:
            raise ValueError(f"download {index} end_time must be after start_time")
        if type(row.opened) is not bool:
            raise ValueError(f"download {index} opened must be bool")
        if row.opened:
            last_access = _windows_microseconds(
                row.last_access_time_windows_us,
                where=f"download {index} last_access_time",
            )
            if last_access < end:
                raise ValueError(
                    f"download {index} last_access_time must not precede end_time"
                )
        else:
            if type(row.last_access_time_windows_us) is not int or (
                row.last_access_time_windows_us != 0
            ):
                raise ValueError(
                    f"download {index} unopened row requires exact integer last_access_time=0"
                )
            last_access = 0
        identity = (target_path.casefold(), row.sha256)
        if identity in identities:
            raise ValueError(f"download {index} duplicates a target/hash identity")
        identities.add(identity)
        prepared.append(
            (
                index,
                _download_guid(identity_seed, index, target_path, row.sha256),
                target_path,
                source_url,
                referrer_url,
                row.size,
                start,
                end,
                int(row.opened),
                last_access,
            )
        )

    main_rows = []
    chain_rows = []
    for (
        rowid,
        guid,
        target_path,
        source_url,
        referrer_url,
        size,
        start,
        end,
        opened,
        last_access,
    ) in prepared:
        site_url = source_url.split("/", 3)[:3]
        origin = "/".join(site_url) + "/"
        main_rows.append(
            (
                rowid,
                guid,
                target_path,
                target_path,
                start,
                size,
                size,
                1,
                0,
                0,
                b"",
                end,
                opened,
                last_access,
                0,
                referrer_url,
                origin,
                "",
                referrer_url,
                "",
                "GET",
                "",
                "",
                "",
                "",
                "",
                "application/x-msdownload",
                "application/x-msdownload",
            )
        )
        chain_rows.append((rowid, 0, source_url))

    return build_sqlite(
        (
            TableSpec(
                "downloads",
                (
                    ColumnSpec("id", "INTEGER", primary_key=True),
                    ColumnSpec("guid", "TEXT"),
                    ColumnSpec("current_path", "TEXT"),
                    ColumnSpec("target_path", "TEXT"),
                    ColumnSpec("start_time", "INTEGER"),
                    ColumnSpec("received_bytes", "INTEGER"),
                    ColumnSpec("total_bytes", "INTEGER"),
                    ColumnSpec("state", "INTEGER"),
                    ColumnSpec("danger_type", "INTEGER"),
                    ColumnSpec("interrupt_reason", "INTEGER"),
                    ColumnSpec("hash", "BLOB"),
                    ColumnSpec("end_time", "INTEGER"),
                    ColumnSpec("opened", "INTEGER"),
                    ColumnSpec("last_access_time", "INTEGER"),
                    ColumnSpec("transient", "INTEGER"),
                    ColumnSpec("referrer", "TEXT"),
                    ColumnSpec("site_url", "TEXT"),
                    ColumnSpec("embedder_download_data", "TEXT"),
                    ColumnSpec("tab_url", "TEXT"),
                    ColumnSpec("tab_referrer_url", "TEXT"),
                    ColumnSpec("http_method", "TEXT"),
                    ColumnSpec("by_ext_id", "TEXT"),
                    ColumnSpec("by_ext_name", "TEXT"),
                    ColumnSpec("by_web_app_id", "TEXT"),
                    ColumnSpec("etag", "TEXT"),
                    ColumnSpec("last_modified", "TEXT"),
                    ColumnSpec("mime_type", "TEXT"),
                    ColumnSpec("original_mime_type", "TEXT"),
                ),
                tuple(main_rows),
            ),
            TableSpec(
                "downloads_url_chains",
                (
                    ColumnSpec("id", "INTEGER"),
                    ColumnSpec("chain_index", "INTEGER"),
                    ColumnSpec("url", "TEXT"),
                ),
                tuple(chain_rows),
            ),
            _marker_table(),
        )
    )


__all__ = [
    "CHROMIUM_DOWNLOAD_PROFILE",
    "ChromiumDownload",
    "WINDOWS_EPOCH_MICROSECONDS",
    "build_chromium_history",
]
