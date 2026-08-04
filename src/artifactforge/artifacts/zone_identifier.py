# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Bounded production-style parser for the emitted Windows ``Zone.Identifier`` ADS.

Fixture ABI v2 stores the stream bytes in its logical manifest rather than applying an ADS to
the development host.  This parser uses the standard-library INI implementation and exposes a
small typed observation.  Gate 1 pairs it with a separately implemented byte reader before
applying ArtifactForge's closed stream profile.
"""
from __future__ import annotations

import configparser
from dataclasses import dataclass
from urllib.parse import urlsplit

from artifactforge.disclosure import MARKER


MAX_ZONE_IDENTIFIER_BYTES = 2048
MAX_ZONE_IDENTIFIER_URL_BYTES = 512
ZONE_IDENTIFIER_SECTION = "ZoneTransfer"
ZONE_IDENTIFIER_KEYS = ("ZoneId", "ReferrerUrl", "HostUrl")


@dataclass(frozen=True)
class ZoneIdentifierValue:
    """One typed observation returned by the production-style INI parser."""

    section: str
    key_order: tuple[str, ...]
    zone_id: int
    referrer_url: str
    host_url: str


def _reserved_https_url(value: object, *, where: str) -> str:
    value = _bounded_ascii_value(
        value, where=where, max_bytes=MAX_ZONE_IDENTIFIER_URL_BYTES
    )
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


def _bounded_ascii_value(value: str, *, where: str, max_bytes: int) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{where} must be non-empty text")
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{where} must be strict ASCII") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"{where} exceeds the {max_bytes}-byte limit")
    if any(byte < 0x20 or byte == 0x7F for byte in encoded):
        raise ValueError(f"{where} contains a control character")
    return value


def parse_zone_identifier(data: bytes) -> ZoneIdentifierValue:
    """Parse one bounded CRLF-framed ``Zone.Identifier`` value with ``ConfigParser``.

    The parser owns the structural input boundary.  Gate 1 separately checks parser
    consensus, exact field order and the emitted Internet-zone/reserved-URL semantics.
    """
    if type(data) is not bytes:
        raise ValueError("Zone.Identifier value must be immutable bytes")
    if not 1 <= len(data) <= MAX_ZONE_IDENTIFIER_BYTES:
        raise ValueError(
            "Zone.Identifier value must contain 1.."
            f"{MAX_ZONE_IDENTIFIER_BYTES} bytes"
        )
    if not data.endswith(b"\r\n"):
        raise ValueError("Zone.Identifier must end with CRLF")
    without_crlf = data.replace(b"\r\n", b"")
    if b"\r" in without_crlf or b"\n" in without_crlf:
        raise ValueError("Zone.Identifier must use CRLF line endings exclusively")
    try:
        text = data.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("Zone.Identifier must be strict ASCII") from exc
    if any(ord(character) < 0x20 and character not in "\r\n" for character in text):
        raise ValueError("Zone.Identifier contains a control character")

    parser = configparser.ConfigParser(
        allow_no_value=False,
        comment_prefixes=(),
        delimiters=("=",),
        empty_lines_in_values=False,
        inline_comment_prefixes=(),
        interpolation=None,
        strict=True,
    )
    parser.optionxform = str
    try:
        parser.read_string(text, source="Zone.Identifier")
    except configparser.Error as exc:
        raise ValueError(f"Zone.Identifier is not strict INI: {exc}") from exc
    if parser.defaults():
        raise ValueError("Zone.Identifier must not contain INI defaults")
    if parser.sections() != [ZONE_IDENTIFIER_SECTION]:
        raise ValueError("Zone.Identifier must contain exactly [ZoneTransfer]")

    section = parser[ZONE_IDENTIFIER_SECTION]
    key_order = tuple(section)
    if set(key_order) != set(ZONE_IDENTIFIER_KEYS) or len(key_order) != len(
        ZONE_IDENTIFIER_KEYS
    ):
        raise ValueError("Zone.Identifier must contain exactly three declared keys")
    zone_text = section["ZoneId"]
    if (
        not zone_text
        or len(zone_text) > 10
        or any(character not in "0123456789" for character in zone_text)
        or (len(zone_text) > 1 and zone_text[0] == "0")
    ):
        raise ValueError("ZoneId must be a bounded canonical decimal integer")
    referrer_url = _bounded_ascii_value(
        section["ReferrerUrl"],
        where="Zone.Identifier ReferrerUrl",
        max_bytes=MAX_ZONE_IDENTIFIER_URL_BYTES,
    )
    host_url = _bounded_ascii_value(
        section["HostUrl"],
        where="Zone.Identifier HostUrl",
        max_bytes=MAX_ZONE_IDENTIFIER_URL_BYTES,
    )
    return ZoneIdentifierValue(
        section=ZONE_IDENTIFIER_SECTION,
        key_order=key_order,
        zone_id=int(zone_text, 10),
        referrer_url=referrer_url,
        host_url=host_url,
    )


def build_zone_identifier(referrer_url: str, host_url: str, *, zone_id: int = 3) -> bytes:
    """Serialize the closed Chromium/Windows Internet-zone stream profile.

    The emitted order and CRLF framing are intentional byte-contract choices.  Windows can
    add other fields under different producers and OS configurations; this builder claims
    only the exact three-key profile parsed above.
    """
    if type(zone_id) is not int or zone_id != 3:
        raise ValueError("Zone.Identifier builder requires exact integer Internet ZoneId=3")
    referrer_url = _reserved_https_url(referrer_url, where="Zone.Identifier ReferrerUrl")
    host_url = _reserved_https_url(host_url, where="Zone.Identifier HostUrl")
    data = (
        b"[ZoneTransfer]\r\n"
        b"ZoneId=3\r\n"
        + b"ReferrerUrl="
        + referrer_url.encode("ascii")
        + b"\r\nHostUrl="
        + host_url.encode("ascii")
        + b"\r\n"
    )
    parse_zone_identifier(data)
    return data


__all__ = [
    "MAX_ZONE_IDENTIFIER_BYTES",
    "MAX_ZONE_IDENTIFIER_URL_BYTES",
    "ZONE_IDENTIFIER_KEYS",
    "ZONE_IDENTIFIER_SECTION",
    "ZoneIdentifierValue",
    "build_zone_identifier",
    "parse_zone_identifier",
]
