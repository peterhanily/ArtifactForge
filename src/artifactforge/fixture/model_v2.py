# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Strict, answer-free Fixture ABI v2 records.

V2 describes a logical guest filesystem without applying that metadata to the development
host.  Every directory and regular file is explicit.  Guest paths map reversibly into a
portable served namespace, while the tree digest binds paths, default-stream bytes, modes,
owners, timestamps, extended attributes, and alternate data streams.

This module is deliberately a data-model layer. Producer availability is a separate runtime
registry decision in :mod:`artifactforge.fixture.abi`, rather than a property inferred from a
schema record or package version.
"""
from __future__ import annotations

import base64
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import hashlib
from itertools import islice
import re
import unicodedata

from artifactforge.fixture.abi import (
    CANONICALIZATION_V1,
    GENERATOR_ABI_V2,
    MANIFEST_SCHEMA_V2,
    PRODUCER_PROFILE_V2,
    SPEC_SCHEMA_V2,
    TREE_CANONICALIZATION_V2,
)
from artifactforge.fixture.canonical import (
    JSONValue,
    canonical_json_bytes,
    load_canonical_json,
    load_json_strict,
)
from artifactforge.fixture.causal import CausalClockError, CausalClockSpec
from artifactforge.fixture.model import FixtureValidationError
from artifactforge.fixture import resources
from artifactforge.inventory import InventoryError, validate_relative_path


SPEC_PURPOSE_V2 = "public-reproducible-fixture"
GENERATOR_NAME_V2 = "artifactforge"
PAYLOAD_ROOT_V2 = "artifacts"

PROFILE_FAMILIES_V2 = {
    "windows-loose-v2": "windows",
    "macos-14-loose-v2": "macos",
    "linux-glibc-x86_64-loose-v2": "linux",
}

LINUX_METADATA_SCHEMA_V2 = "artifactforge-linux-posix-metadata-v2"
MACOS_METADATA_SCHEMA_V2 = "artifactforge-macos-metadata-v2"
WINDOWS_METADATA_SCHEMA_V2 = "artifactforge-windows-metadata-v2"

RECIPE_DIGEST_DOMAIN_V2 = "artifactforge-fixture-recipe-digest-v2"
TREE_DIGEST_DOMAIN_V2 = "artifactforge-fixture-tree-digest-v2"
CLOCK_CONTEXT_DOMAIN_V2 = "artifactforge-fixture-clock-context-v2"
SCENE_KEY_DOMAIN_V2 = b"artifactforge/fixture/scene-key/v2\0"
CONTENT_STORE_NAMESPACE_V2 = "artifactforge::fixture/v2"

MAX_V2_FILES = 256
MAX_V2_DIRECTORIES = 512
MAX_V2_NODES = MAX_V2_FILES + MAX_V2_DIRECTORIES
MAX_V2_PATH_SEGMENTS = 32
MAX_V2_SERVED_PATH_BYTES = 240
MAX_V2_GUEST_PATH_BYTES = 1024
MAX_V2_BLOBS_PER_NODE = 16
MAX_V2_BLOB_NAME_BYTES = 255
MAX_V2_BLOB_BYTES = 64 * 1024
MAX_V2_BLOB_BASE64_CHARS = 4 * ((MAX_V2_BLOB_BYTES + 2) // 3)
MAX_V2_METADATA_BLOBS = MAX_V2_NODES * MAX_V2_BLOBS_PER_NODE
MAX_V2_METADATA_BLOB_BYTES = 1024 * 1024
MAX_V2_BOUND_BYTES = 64 * 1024 * 1024
MAX_V2_OWNER_ID = (1 << 31) - 1
MAX_V2_UNIX_NS = (1 << 63) - 1
MAX_V2_GENERATOR_VERSION_BYTES = 128
MAX_V2_SID_BYTES = 184

_FIXTURE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SEED_HEX = re.compile(r"^[0-9a-f]{64}$")
_LABELLED_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_BLOB_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._$-]{0,254}$")
_CANONICAL_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)$")
_SID = re.compile(
    r"^S-1-(?:0|[1-9][0-9]{0,14})(?:-(?:0|[1-9][0-9]{0,9})){1,15}$"
)

WINDOWS_ATTRIBUTES_V2 = frozenset(
    {
        "ARCHIVE",
        "COMPRESSED",
        "DIRECTORY",
        "ENCRYPTED",
        "HIDDEN",
        "NORMAL",
        "NOT_CONTENT_INDEXED",
        "OFFLINE",
        "READONLY",
        "SYSTEM",
        "TEMPORARY",
    }
)
_WINDOWS_RESERVED_COMPONENTS = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


class FixtureV2ValidationError(FixtureValidationError):
    """A v2 recipe, manifest, path, node, or logical metadata value is invalid."""


def _as_mapping(value: object, where: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise FixtureV2ValidationError(f"{where} must be an object")
    if not all(isinstance(key, str) for key in value):
        raise FixtureV2ValidationError(f"{where} object member names must be strings")
    return value


def _exact_keys(value: Mapping[str, object], expected: set[str], where: str) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if not missing and not unknown:
        return
    details: list[str] = []
    if missing:
        details.append("missing " + ", ".join(repr(item) for item in missing))
    if unknown:
        details.append("unknown " + ", ".join(repr(item) for item in unknown))
    raise FixtureV2ValidationError(f"{where} has " + "; ".join(details))


def _text(
    value: object,
    where: str,
    *,
    nonempty: bool = True,
    printable_ascii: bool = False,
) -> str:
    if not isinstance(value, str):
        raise FixtureV2ValidationError(f"{where} must be a string")
    if nonempty and not value:
        raise FixtureV2ValidationError(f"{where} must not be empty")
    if unicodedata.normalize("NFC", value) != value:
        raise FixtureV2ValidationError(f"{where} must be Unicode NFC")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise FixtureV2ValidationError(f"{where} contains an unpaired Unicode surrogate") from exc
    if printable_ascii and any(byte < 0x20 or byte > 0x7E for byte in encoded):
        raise FixtureV2ValidationError(f"{where} must be printable ASCII")
    if not printable_ascii and any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise FixtureV2ValidationError(f"{where} must not contain control characters")
    return value


def _integer(
    value: object,
    where: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if type(value) is not int:
        raise FixtureV2ValidationError(f"{where} must be an integer")
    if value < minimum:
        raise FixtureV2ValidationError(f"{where} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise FixtureV2ValidationError(f"{where} must be at most {maximum}")
    return value


def _constant(value: object, expected: object, where: str) -> None:
    if value != expected or type(value) is not type(expected):
        raise FixtureV2ValidationError(f"{where} must be {expected!r}")


def _labelled_sha256(value: object, where: str) -> str:
    text = _text(value, where, printable_ascii=True)
    if _LABELLED_SHA256.fullmatch(text) is None:
        raise FixtureV2ValidationError(
            f"{where} must be 'sha256:' plus 64 lowercase hex digits"
        )
    return text


def _domain_sha256(domain: str, value: object) -> str:
    digest = hashlib.sha256(domain.encode("ascii") + b"\0" + canonical_json_bytes(value))
    return "sha256:" + digest.hexdigest()


def _bounded_values(
    values: Iterable[object],
    *,
    maximum: int,
    where: str,
) -> tuple[object, ...]:
    if isinstance(values, (str, bytes, Mapping)):
        raise FixtureV2ValidationError(f"{where} must be a sequence")
    try:
        result = tuple(islice(iter(values), maximum + 1))
    except TypeError as exc:
        raise FixtureV2ValidationError(f"{where} must be a sequence") from exc
    if len(result) > maximum:
        raise FixtureV2ValidationError(f"{where} exceeds the {maximum}-item limit")
    return result


def _validate_blob_name(value: object, where: str) -> str:
    name = _text(value, where, printable_ascii=True)
    if len(name.encode("ascii")) > MAX_V2_BLOB_NAME_BYTES or _BLOB_NAME.fullmatch(name) is None:
        raise FixtureV2ValidationError(
            f"{where} must be 1..{MAX_V2_BLOB_NAME_BYTES} portable ASCII name bytes"
        )
    return name


def _validate_served_path(path: object) -> str:
    value = _text(path, "served path", printable_ascii=True)
    if len(value.encode("ascii")) > MAX_V2_SERVED_PATH_BYTES:
        raise FixtureV2ValidationError(
            f"served path exceeds the {MAX_V2_SERVED_PATH_BYTES}-byte limit"
        )
    try:
        validated = validate_relative_path(value)
    except InventoryError as exc:
        raise FixtureV2ValidationError(str(exc)) from exc
    if len(validated.split("/")) > MAX_V2_PATH_SEGMENTS:
        raise FixtureV2ValidationError(
            f"served path exceeds the {MAX_V2_PATH_SEGMENTS}-segment limit"
        )
    return validated


def _validate_windows_component(component: str, where: str) -> None:
    if not component or component in {".", ".."}:
        raise FixtureV2ValidationError(f"{where} has an empty, '.' or '..' component")
    if component.endswith((" ", ".")):
        raise FixtureV2ValidationError(f"{where} has a component ending in a dot or space")
    if any(character in '<>:"/|?*\\' for character in component):
        raise FixtureV2ValidationError(f"{where} has a forbidden Windows path character")
    stem = component.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED_COMPONENTS:
        raise FixtureV2ValidationError(f"{where} uses reserved Windows name {component!r}")


def guest_path_to_served_path(family: str, guest_path: object) -> str:
    """Return the exact portable carrier spelling for one canonical absolute guest path."""
    if family not in {"windows", "macos", "linux"}:
        raise FixtureV2ValidationError("guest path family must be windows, macos or linux")
    guest = _text(guest_path, "guest path", printable_ascii=True)
    if len(guest.encode("ascii")) > MAX_V2_GUEST_PATH_BYTES:
        raise FixtureV2ValidationError(
            f"guest path exceeds the {MAX_V2_GUEST_PATH_BYTES}-byte limit"
        )
    if family in {"macos", "linux"}:
        if not guest.startswith("/") or guest.startswith("//") or guest.endswith("/"):
            raise FixtureV2ValidationError(
                "POSIX guest path must have exactly one leading slash and no trailing slash"
            )
        if "\\" in guest:
            raise FixtureV2ValidationError("POSIX guest path must not contain a backslash")
        parts = guest[1:].split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise FixtureV2ValidationError(
                "POSIX guest path has an empty, '.' or '..' component"
            )
        return _validate_served_path("/".join(parts))

    if len(guest) < 3 or guest[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" or guest[1:3] != ":\\":
        raise FixtureV2ValidationError(
            "Windows guest path must begin with one uppercase drive and ':\\\\'"
        )
    if "/" in guest:
        raise FixtureV2ValidationError("Windows guest path must use backslash separators")
    remainder = guest[3:]
    parts = [] if not remainder else remainder.split("\\")
    if any(not part for part in parts):
        raise FixtureV2ValidationError("Windows guest path has an empty component")
    for part in parts:
        _validate_windows_component(part, "Windows guest path")
    served = "/".join((guest[0], *parts))
    return _validate_served_path(served)


def served_path_to_guest_path(family: str, served_path: object) -> str:
    """Invert :func:`guest_path_to_served_path` without normalization or guessing."""
    served = _validate_served_path(served_path)
    if family in {"macos", "linux"}:
        guest = "/" + served
    elif family == "windows":
        parts = served.split("/")
        if len(parts[0]) != 1 or parts[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            raise FixtureV2ValidationError(
                "Windows served path must start with one uppercase drive component"
            )
        for part in parts[1:]:
            _validate_windows_component(part, "Windows served path")
        guest = parts[0] + ":\\" + "\\".join(parts[1:])
    else:
        raise FixtureV2ValidationError("served path family must be windows, macos or linux")
    if guest_path_to_served_path(family, guest) != served:
        raise FixtureV2ValidationError("served path is not a reversible guest-path mapping")
    return guest


def validate_ustar_member_name_v2(name: object) -> str:
    """Require one ASCII member name to fit USTAR's 155-byte prefix and 100-byte name.

    This validates the final release spelling, not merely the served payload suffix.  Long
    names are accepted only when an existing slash supplies an exact prefix/name split; PAX
    and GNU extension records are never an implicit fallback.
    """
    value = _text(name, "USTAR member name", printable_ascii=True)
    encoded = value.encode("ascii")
    if len(encoded) <= 100:
        return value
    slash_offsets = [index for index, byte in enumerate(encoded[:-1]) if byte == ord("/")]
    if any(
        offset <= 155
        and len(encoded) - offset - 1 <= 100
        and len(encoded) - offset - 1 > 0
        for offset in slash_offsets
    ):
        return value
    raise FixtureV2ValidationError(
        "USTAR member name cannot be represented without a PAX/GNU extension: "
        f"{value!r}"
    )


@dataclass(frozen=True)
class ProfileSpecV2:
    id: str
    hostname: str
    username: str

    def __post_init__(self) -> None:
        profile_id = _text(self.id, "profile.id", printable_ascii=True)
        if profile_id not in PROFILE_FAMILIES_V2:
            choices = ", ".join(sorted(PROFILE_FAMILIES_V2))
            raise FixtureV2ValidationError(f"profile.id must be one of: {choices}")
        hostname = _text(self.hostname, "profile.hostname", printable_ascii=True)
        if _HOSTNAME.fullmatch(hostname) is None:
            raise FixtureV2ValidationError("profile.hostname is outside the v2 ASCII profile")
        username = _text(self.username, "profile.username", printable_ascii=True)
        if _USERNAME.fullmatch(username) is None:
            raise FixtureV2ValidationError("profile.username is outside the v2 ASCII profile")
        if PROFILE_FAMILIES_V2[profile_id] == "windows":
            _validate_windows_component(username, "profile.username")

    @classmethod
    def from_mapping(cls, value: object) -> ProfileSpecV2:
        mapping = _as_mapping(value, "profile")
        _exact_keys(mapping, {"id", "hostname", "username"}, "profile")
        return cls(
            id=_text(mapping["id"], "profile.id", printable_ascii=True),
            hostname=_text(mapping["hostname"], "profile.hostname", printable_ascii=True),
            username=_text(mapping["username"], "profile.username", printable_ascii=True),
        )

    def to_mapping(self) -> dict[str, JSONValue]:
        return {"id": self.id, "hostname": self.hostname, "username": self.username}


def _clock_context_v2(
    *, fixture_id: str, family: str, profile: ProfileSpecV2
) -> bytes:
    """Canonical answer-free projection used by the one v2 clock derivation path."""
    return canonical_json_bytes(
        {
            "domain": CLOCK_CONTEXT_DOMAIN_V2,
            "fixture_id": fixture_id,
            "family": family,
            "profile": profile.to_mapping(),
        }
    )


def _clock_from_mapping(value: object) -> CausalClockSpec:
    mapping = _as_mapping(value, "spec.causal_clock")
    _exact_keys(mapping, {"profile", "anchor_unix_ns"}, "spec.causal_clock")
    try:
        return CausalClockSpec(
            profile=_text(mapping["profile"], "spec.causal_clock.profile", printable_ascii=True),
            anchor_unix_ns=_integer(
                mapping["anchor_unix_ns"],
                "spec.causal_clock.anchor_unix_ns",
                maximum=MAX_V2_UNIX_NS,
            ),
        )
    except CausalClockError as exc:
        raise FixtureV2ValidationError(f"invalid causal clock: {exc}") from exc


@dataclass(frozen=True)
class FixtureSpecV2:
    fixture_id: str
    family: str
    profile: ProfileSpecV2
    seed_hex: str
    causal_clock: CausalClockSpec
    schema: str = SPEC_SCHEMA_V2
    purpose: str = SPEC_PURPOSE_V2

    def __post_init__(self) -> None:
        _constant(self.schema, SPEC_SCHEMA_V2, "spec.schema")
        _constant(self.purpose, SPEC_PURPOSE_V2, "spec.purpose")
        fixture_id = _text(self.fixture_id, "spec.fixture_id", printable_ascii=True)
        if _FIXTURE_ID.fullmatch(fixture_id) is None:
            raise FixtureV2ValidationError(
                "spec.fixture_id must match [a-z0-9][a-z0-9._-]{0,63}"
            )
        family = _text(self.family, "spec.family", printable_ascii=True)
        if family not in {"windows", "macos", "linux"}:
            raise FixtureV2ValidationError("spec.family must be windows, macos or linux")
        if type(self.profile) is not ProfileSpecV2:
            raise FixtureV2ValidationError("spec.profile must be a ProfileSpecV2")
        expected_family = PROFILE_FAMILIES_V2[self.profile.id]
        if family != expected_family:
            raise FixtureV2ValidationError(
                f"profile {self.profile.id!r} belongs to {expected_family!r}, not {family!r}"
            )
        seed = _text(self.seed_hex, "spec.seed_hex", printable_ascii=True)
        if _SEED_HEX.fullmatch(seed) is None:
            raise FixtureV2ValidationError(
                "spec.seed_hex must be exactly 64 lowercase hexadecimal digits"
            )
        if type(self.causal_clock) is not CausalClockSpec:
            raise FixtureV2ValidationError("spec.causal_clock must be a CausalClockSpec")
        try:
            expected_clock = CausalClockSpec.from_seed_hex(
                seed,
                context=_clock_context_v2(
                    fixture_id=fixture_id,
                    family=family,
                    profile=self.profile,
                ),
            )
        except CausalClockError as exc:  # pragma: no cover - seed was already validated.
            raise FixtureV2ValidationError(f"cannot derive causal clock: {exc}") from exc
        if self.causal_clock != expected_clock:
            raise FixtureV2ValidationError(
                "spec.causal_clock does not match its seed and canonical recipe context"
            )

    @classmethod
    def create(
        cls,
        *,
        fixture_id: str,
        family: str,
        profile: ProfileSpecV2,
        seed_hex: str,
    ) -> FixtureSpecV2:
        return cls(
            fixture_id=fixture_id,
            family=family,
            profile=profile,
            seed_hex=seed_hex,
            causal_clock=CausalClockSpec.from_seed_hex(
                seed_hex,
                context=_clock_context_v2(
                    fixture_id=fixture_id,
                    family=family,
                    profile=profile,
                ),
            ),
        )

    @classmethod
    def from_mapping(cls, value: object) -> FixtureSpecV2:
        mapping = _as_mapping(value, "spec")
        _exact_keys(
            mapping,
            {
                "schema",
                "purpose",
                "fixture_id",
                "family",
                "profile",
                "seed_hex",
                "causal_clock",
            },
            "spec",
        )
        return cls(
            schema=_text(mapping["schema"], "spec.schema", printable_ascii=True),
            purpose=_text(mapping["purpose"], "spec.purpose", printable_ascii=True),
            fixture_id=_text(mapping["fixture_id"], "spec.fixture_id", printable_ascii=True),
            family=_text(mapping["family"], "spec.family", printable_ascii=True),
            profile=ProfileSpecV2.from_mapping(mapping["profile"]),
            seed_hex=_text(mapping["seed_hex"], "spec.seed_hex", printable_ascii=True),
            causal_clock=_clock_from_mapping(mapping["causal_clock"]),
        )

    @classmethod
    def from_json(cls, data: bytes | str) -> FixtureSpecV2:
        return cls.from_mapping(load_json_strict(data))

    def to_mapping(self) -> dict[str, JSONValue]:
        clock = self.causal_clock.to_mapping()
        return {
            "schema": self.schema,
            "purpose": self.purpose,
            "fixture_id": self.fixture_id,
            "family": self.family,
            "profile": self.profile.to_mapping(),
            "seed_hex": self.seed_hex,
            "causal_clock": {
                "profile": str(clock["profile"]),
                "anchor_unix_ns": int(clock["anchor_unix_ns"]),
            },
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_mapping())

    @property
    def recipe_sha256(self) -> str:
        return _domain_sha256(RECIPE_DIGEST_DOMAIN_V2, self.to_mapping())


def compute_recipe_sha256_v2(spec: FixtureSpecV2) -> str:
    if type(spec) is not FixtureSpecV2:
        raise TypeError("v2 recipe digest input must be a FixtureSpecV2")
    return spec.recipe_sha256


@dataclass(frozen=True)
class NamedBlobV2:
    """One canonical inline xattr or ADS value with redundant byte integrity equations."""

    name: str
    data_base64: str
    size: int
    sha256: str

    def __post_init__(self) -> None:
        _validate_blob_name(self.name, "metadata blob name")
        size = _integer(
            self.size,
            f"metadata blob {self.name!r} size",
            maximum=MAX_V2_BLOB_BYTES,
        )
        expected_sha256 = _labelled_sha256(
            self.sha256, f"metadata blob {self.name!r} sha256"
        )
        encoded = _text(
            self.data_base64,
            f"metadata blob {self.name!r} data_base64",
            nonempty=False,
            printable_ascii=True,
        )
        if len(encoded) > MAX_V2_BLOB_BASE64_CHARS:
            raise FixtureV2ValidationError(
                f"metadata blob {self.name!r} base64 exceeds the encoded length limit"
            )
        if len(encoded) % 4:
            raise FixtureV2ValidationError(
                f"metadata blob {self.name!r} base64 must use canonical RFC 4648 padding"
            )
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise FixtureV2ValidationError(
                f"metadata blob {self.name!r} is not strict RFC 4648 base64"
            ) from exc
        if base64.b64encode(decoded).decode("ascii") != encoded:
            raise FixtureV2ValidationError(
                f"metadata blob {self.name!r} base64 is not canonically padded"
            )
        if len(decoded) != size:
            raise FixtureV2ValidationError(
                f"metadata blob {self.name!r} size does not equal decoded bytes"
            )
        actual_sha256 = "sha256:" + hashlib.sha256(decoded).hexdigest()
        if expected_sha256 != actual_sha256:
            raise FixtureV2ValidationError(
                f"metadata blob {self.name!r} sha256 mismatch: expected {actual_sha256}"
            )

    @classmethod
    def from_bytes(cls, name: str, data: bytes) -> NamedBlobV2:
        if not isinstance(data, bytes):
            raise TypeError("metadata blob data must be bytes")
        if len(data) > MAX_V2_BLOB_BYTES:
            raise FixtureV2ValidationError(
                f"metadata blob exceeds the {MAX_V2_BLOB_BYTES}-byte limit"
            )
        return cls(
            name=name,
            data_base64=base64.b64encode(data).decode("ascii"),
            size=len(data),
            sha256="sha256:" + hashlib.sha256(data).hexdigest(),
        )

    @classmethod
    def from_mapping(cls, value: object, *, where: str) -> NamedBlobV2:
        mapping = _as_mapping(value, where)
        _exact_keys(mapping, {"name", "data_base64", "size", "sha256"}, where)
        return cls(
            name=_validate_blob_name(mapping["name"], f"{where}.name"),
            data_base64=_text(
                mapping["data_base64"],
                f"{where}.data_base64",
                nonempty=False,
                printable_ascii=True,
            ),
            size=_integer(mapping["size"], f"{where}.size", maximum=MAX_V2_BLOB_BYTES),
            sha256=_labelled_sha256(mapping["sha256"], f"{where}.sha256"),
        )

    @property
    def data(self) -> bytes:
        return base64.b64decode(self.data_base64, validate=True)

    def to_mapping(self) -> dict[str, JSONValue]:
        return {
            "name": self.name,
            "data_base64": self.data_base64,
            "size": self.size,
            "sha256": self.sha256,
        }


def _validated_blobs(
    values: Iterable[NamedBlobV2],
    *,
    where: str,
    casefold_unique: bool,
) -> tuple[NamedBlobV2, ...]:
    raw = _bounded_values(values, maximum=MAX_V2_BLOBS_PER_NODE, where=where)
    blobs: list[NamedBlobV2] = []
    for index, value in enumerate(raw):
        if type(value) is not NamedBlobV2:
            raise FixtureV2ValidationError(f"{where}[{index}] must be a NamedBlobV2")
        blobs.append(value)
    names = tuple(blob.name for blob in blobs)
    if names != tuple(sorted(names)):
        raise FixtureV2ValidationError(f"{where} must be sorted by name")
    if len(set(names)) != len(names):
        raise FixtureV2ValidationError(f"{where} contains a duplicate name")
    if casefold_unique:
        folded: dict[str, str] = {}
        for name in names:
            previous = folded.get(name.casefold())
            if previous is not None and previous != name:
                raise FixtureV2ValidationError(
                    f"{where} contains case-folding aliases {previous!r} and {name!r}"
                )
            folded[name.casefold()] = name
    return tuple(blobs)


def _validate_posix_fields(
    *,
    mode: object,
    uid: object,
    gid: object,
    atime_unix_ns: object,
    mtime_unix_ns: object,
    ctime_unix_ns: object,
    where: str,
) -> None:
    _integer(mode, f"{where}.mode", maximum=0o7777)
    _integer(uid, f"{where}.uid", maximum=MAX_V2_OWNER_ID)
    _integer(gid, f"{where}.gid", maximum=MAX_V2_OWNER_ID)
    _integer(atime_unix_ns, f"{where}.atime_unix_ns", maximum=MAX_V2_UNIX_NS)
    _integer(mtime_unix_ns, f"{where}.mtime_unix_ns", maximum=MAX_V2_UNIX_NS)
    _integer(ctime_unix_ns, f"{where}.ctime_unix_ns", maximum=MAX_V2_UNIX_NS)


@dataclass(frozen=True)
class LinuxMetadataV2:
    mode: int
    uid: int
    gid: int
    atime_unix_ns: int
    mtime_unix_ns: int
    ctime_unix_ns: int
    schema: str = LINUX_METADATA_SCHEMA_V2

    def __post_init__(self) -> None:
        _constant(self.schema, LINUX_METADATA_SCHEMA_V2, "Linux metadata.schema")
        _validate_posix_fields(
            mode=self.mode,
            uid=self.uid,
            gid=self.gid,
            atime_unix_ns=self.atime_unix_ns,
            mtime_unix_ns=self.mtime_unix_ns,
            ctime_unix_ns=self.ctime_unix_ns,
            where="Linux metadata",
        )

    @classmethod
    def from_mapping(cls, value: object, *, where: str) -> LinuxMetadataV2:
        mapping = _as_mapping(value, where)
        expected = {
            "schema",
            "mode",
            "uid",
            "gid",
            "atime_unix_ns",
            "mtime_unix_ns",
            "ctime_unix_ns",
        }
        _exact_keys(mapping, expected, where)
        return cls(
            schema=_text(mapping["schema"], f"{where}.schema", printable_ascii=True),
            mode=_integer(mapping["mode"], f"{where}.mode", maximum=0o7777),
            uid=_integer(mapping["uid"], f"{where}.uid", maximum=MAX_V2_OWNER_ID),
            gid=_integer(mapping["gid"], f"{where}.gid", maximum=MAX_V2_OWNER_ID),
            atime_unix_ns=_integer(
                mapping["atime_unix_ns"], f"{where}.atime_unix_ns", maximum=MAX_V2_UNIX_NS
            ),
            mtime_unix_ns=_integer(
                mapping["mtime_unix_ns"], f"{where}.mtime_unix_ns", maximum=MAX_V2_UNIX_NS
            ),
            ctime_unix_ns=_integer(
                mapping["ctime_unix_ns"], f"{where}.ctime_unix_ns", maximum=MAX_V2_UNIX_NS
            ),
        )

    def to_mapping(self) -> dict[str, JSONValue]:
        return {
            "schema": self.schema,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "atime_unix_ns": self.atime_unix_ns,
            "mtime_unix_ns": self.mtime_unix_ns,
            "ctime_unix_ns": self.ctime_unix_ns,
        }


@dataclass(frozen=True)
class MacOSMetadataV2:
    mode: int
    uid: int
    gid: int
    atime_unix_ns: int
    mtime_unix_ns: int
    ctime_unix_ns: int
    birthtime_unix_ns: int
    xattrs: tuple[NamedBlobV2, ...] = ()
    schema: str = MACOS_METADATA_SCHEMA_V2

    def __post_init__(self) -> None:
        _constant(self.schema, MACOS_METADATA_SCHEMA_V2, "macOS metadata.schema")
        _validate_posix_fields(
            mode=self.mode,
            uid=self.uid,
            gid=self.gid,
            atime_unix_ns=self.atime_unix_ns,
            mtime_unix_ns=self.mtime_unix_ns,
            ctime_unix_ns=self.ctime_unix_ns,
            where="macOS metadata",
        )
        _integer(
            self.birthtime_unix_ns,
            "macOS metadata.birthtime_unix_ns",
            maximum=MAX_V2_UNIX_NS,
        )
        object.__setattr__(
            self,
            "xattrs",
            # Extended-attribute names use exact POSIX identity in this profile.
            _validated_blobs(
                self.xattrs,
                where="macOS metadata.xattrs",
                casefold_unique=False,
            ),
        )

    @classmethod
    def from_mapping(cls, value: object, *, where: str) -> MacOSMetadataV2:
        mapping = _as_mapping(value, where)
        expected = {
            "schema",
            "mode",
            "uid",
            "gid",
            "atime_unix_ns",
            "mtime_unix_ns",
            "ctime_unix_ns",
            "birthtime_unix_ns",
            "xattrs",
        }
        _exact_keys(mapping, expected, where)
        raw_xattrs = mapping["xattrs"]
        if not isinstance(raw_xattrs, list):
            raise FixtureV2ValidationError(f"{where}.xattrs must be an array")
        return cls(
            schema=_text(mapping["schema"], f"{where}.schema", printable_ascii=True),
            mode=_integer(mapping["mode"], f"{where}.mode", maximum=0o7777),
            uid=_integer(mapping["uid"], f"{where}.uid", maximum=MAX_V2_OWNER_ID),
            gid=_integer(mapping["gid"], f"{where}.gid", maximum=MAX_V2_OWNER_ID),
            atime_unix_ns=_integer(
                mapping["atime_unix_ns"], f"{where}.atime_unix_ns", maximum=MAX_V2_UNIX_NS
            ),
            mtime_unix_ns=_integer(
                mapping["mtime_unix_ns"], f"{where}.mtime_unix_ns", maximum=MAX_V2_UNIX_NS
            ),
            ctime_unix_ns=_integer(
                mapping["ctime_unix_ns"], f"{where}.ctime_unix_ns", maximum=MAX_V2_UNIX_NS
            ),
            birthtime_unix_ns=_integer(
                mapping["birthtime_unix_ns"],
                f"{where}.birthtime_unix_ns",
                maximum=MAX_V2_UNIX_NS,
            ),
            xattrs=tuple(
                NamedBlobV2.from_mapping(item, where=f"{where}.xattrs[{index}]")
                for index, item in enumerate(raw_xattrs)
            ),
        )

    def to_mapping(self) -> dict[str, JSONValue]:
        return {
            "schema": self.schema,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "atime_unix_ns": self.atime_unix_ns,
            "mtime_unix_ns": self.mtime_unix_ns,
            "ctime_unix_ns": self.ctime_unix_ns,
            "birthtime_unix_ns": self.birthtime_unix_ns,
            "xattrs": [blob.to_mapping() for blob in self.xattrs],
        }


def _validate_sid(value: object, where: str) -> str:
    sid = _text(value, where, printable_ascii=True)
    if len(sid.encode("ascii")) > MAX_V2_SID_BYTES:
        raise FixtureV2ValidationError(
            f"{where} exceeds the {MAX_V2_SID_BYTES}-byte SID limit"
        )
    if _SID.fullmatch(sid) is None:
        raise FixtureV2ValidationError(f"{where} must be a canonical decimal SID")
    components = sid.split("-")
    authority = int(components[2])
    subauthorities = tuple(int(item) for item in components[3:])
    if authority >= 1 << 48:
        raise FixtureV2ValidationError(f"{where} authority exceeds 48 bits")
    if any(item >= 1 << 32 for item in subauthorities):
        raise FixtureV2ValidationError(f"{where} subauthority exceeds 32 bits")
    if any(_CANONICAL_DECIMAL.fullmatch(item) is None for item in components[1:]):
        raise FixtureV2ValidationError(f"{where} contains noncanonical decimal components")
    return sid


def _validated_windows_attributes(values: Iterable[str]) -> tuple[str, ...]:
    raw = _bounded_values(
        values,
        maximum=len(WINDOWS_ATTRIBUTES_V2),
        where="Windows metadata.attributes",
    )
    attributes: list[str] = []
    for index, value in enumerate(raw):
        attribute = _text(
            value,
            f"Windows metadata.attributes[{index}]",
            printable_ascii=True,
        )
        if attribute not in WINDOWS_ATTRIBUTES_V2:
            raise FixtureV2ValidationError(
                f"Windows metadata attribute {attribute!r} is outside the closed profile"
            )
        attributes.append(attribute)
    result = tuple(attributes)
    if not result:
        raise FixtureV2ValidationError("Windows metadata.attributes must not be empty")
    if result != tuple(sorted(result)):
        raise FixtureV2ValidationError("Windows metadata.attributes must be sorted")
    if len(set(result)) != len(result):
        raise FixtureV2ValidationError("Windows metadata.attributes contains a duplicate")
    if "NORMAL" in result and result != ("NORMAL",):
        raise FixtureV2ValidationError("Windows NORMAL attribute cannot be combined")
    return result


@dataclass(frozen=True)
class WindowsMetadataV2:
    owner_sid: str
    attributes: tuple[str, ...]
    creation_unix_ns: int
    access_unix_ns: int
    write_unix_ns: int
    change_unix_ns: int
    streams: tuple[NamedBlobV2, ...] = ()
    schema: str = WINDOWS_METADATA_SCHEMA_V2

    def __post_init__(self) -> None:
        _constant(self.schema, WINDOWS_METADATA_SCHEMA_V2, "Windows metadata.schema")
        _validate_sid(self.owner_sid, "Windows metadata.owner_sid")
        object.__setattr__(self, "attributes", _validated_windows_attributes(self.attributes))
        for field_name in (
            "creation_unix_ns",
            "access_unix_ns",
            "write_unix_ns",
            "change_unix_ns",
        ):
            _integer(
                getattr(self, field_name),
                f"Windows metadata.{field_name}",
                maximum=MAX_V2_UNIX_NS,
            )
        object.__setattr__(
            self,
            "streams",
            _validated_blobs(
                self.streams,
                where="Windows metadata.streams",
                casefold_unique=True,
            ),
        )

    @classmethod
    def from_mapping(cls, value: object, *, where: str) -> WindowsMetadataV2:
        mapping = _as_mapping(value, where)
        expected = {
            "schema",
            "owner_sid",
            "attributes",
            "creation_unix_ns",
            "access_unix_ns",
            "write_unix_ns",
            "change_unix_ns",
            "streams",
        }
        _exact_keys(mapping, expected, where)
        raw_attributes = mapping["attributes"]
        raw_streams = mapping["streams"]
        if not isinstance(raw_attributes, list):
            raise FixtureV2ValidationError(f"{where}.attributes must be an array")
        if not isinstance(raw_streams, list):
            raise FixtureV2ValidationError(f"{where}.streams must be an array")
        return cls(
            schema=_text(mapping["schema"], f"{where}.schema", printable_ascii=True),
            owner_sid=_validate_sid(mapping["owner_sid"], f"{where}.owner_sid"),
            attributes=tuple(
                _text(item, f"{where}.attributes[{index}]", printable_ascii=True)
                for index, item in enumerate(raw_attributes)
            ),
            creation_unix_ns=_integer(
                mapping["creation_unix_ns"],
                f"{where}.creation_unix_ns",
                maximum=MAX_V2_UNIX_NS,
            ),
            access_unix_ns=_integer(
                mapping["access_unix_ns"],
                f"{where}.access_unix_ns",
                maximum=MAX_V2_UNIX_NS,
            ),
            write_unix_ns=_integer(
                mapping["write_unix_ns"],
                f"{where}.write_unix_ns",
                maximum=MAX_V2_UNIX_NS,
            ),
            change_unix_ns=_integer(
                mapping["change_unix_ns"],
                f"{where}.change_unix_ns",
                maximum=MAX_V2_UNIX_NS,
            ),
            streams=tuple(
                NamedBlobV2.from_mapping(item, where=f"{where}.streams[{index}]")
                for index, item in enumerate(raw_streams)
            ),
        )

    def to_mapping(self) -> dict[str, JSONValue]:
        return {
            "schema": self.schema,
            "owner_sid": self.owner_sid,
            "attributes": list(self.attributes),
            "creation_unix_ns": self.creation_unix_ns,
            "access_unix_ns": self.access_unix_ns,
            "write_unix_ns": self.write_unix_ns,
            "change_unix_ns": self.change_unix_ns,
            "streams": [blob.to_mapping() for blob in self.streams],
        }


NodeMetadataV2 = LinuxMetadataV2 | MacOSMetadataV2 | WindowsMetadataV2


def _metadata_from_mapping(value: object, *, family: str, where: str) -> NodeMetadataV2:
    mapping = _as_mapping(value, where)
    schema = mapping.get("schema")
    expected = {
        "linux": (LINUX_METADATA_SCHEMA_V2, LinuxMetadataV2.from_mapping),
        "macos": (MACOS_METADATA_SCHEMA_V2, MacOSMetadataV2.from_mapping),
        "windows": (WINDOWS_METADATA_SCHEMA_V2, WindowsMetadataV2.from_mapping),
    }.get(family)
    if expected is None:
        raise FixtureV2ValidationError(f"unsupported metadata family: {family!r}")
    expected_schema, parser = expected
    if schema != expected_schema:
        raise FixtureV2ValidationError(
            f"{where}.schema must be {expected_schema!r} for family {family!r}"
        )
    return parser(mapping, where=where)


def _validate_node_metadata(metadata: object, *, family: str, kind: str, where: str) -> None:
    expected_type = {
        "linux": LinuxMetadataV2,
        "macos": MacOSMetadataV2,
        "windows": WindowsMetadataV2,
    }[family]
    if type(metadata) is not expected_type:
        raise FixtureV2ValidationError(
            f"{where}.metadata must be {expected_type.__name__} for family {family!r}"
        )
    if family != "windows":
        return
    attributes = metadata.attributes
    if kind == "directory" and "DIRECTORY" not in attributes:
        raise FixtureV2ValidationError(
            f"{where} directory metadata must include the DIRECTORY attribute"
        )
    if kind == "file" and "DIRECTORY" in attributes:
        raise FixtureV2ValidationError(
            f"{where} file metadata must not include the DIRECTORY attribute"
        )


@dataclass(frozen=True)
class DirectoryNodeV2:
    guest_path: str
    served_path: str
    metadata: NodeMetadataV2

    def __post_init__(self) -> None:
        _text(self.guest_path, "directory.guest_path", printable_ascii=True)
        _validate_served_path(self.served_path)
        if not isinstance(
            self.metadata,
            (LinuxMetadataV2, MacOSMetadataV2, WindowsMetadataV2),
        ):
            raise FixtureV2ValidationError("directory.metadata has an unsupported type")

    @classmethod
    def from_mapping(
        cls,
        value: object,
        *,
        family: str,
        where: str,
    ) -> DirectoryNodeV2:
        mapping = _as_mapping(value, where)
        _exact_keys(mapping, {"guest_path", "served_path", "metadata"}, where)
        return cls(
            guest_path=_text(
                mapping["guest_path"], f"{where}.guest_path", printable_ascii=True
            ),
            served_path=_validate_served_path(mapping["served_path"]),
            metadata=_metadata_from_mapping(
                mapping["metadata"], family=family, where=f"{where}.metadata"
            ),
        )

    def to_mapping(self) -> dict[str, JSONValue]:
        return {
            "guest_path": self.guest_path,
            "served_path": self.served_path,
            "metadata": self.metadata.to_mapping(),
        }


@dataclass(frozen=True)
class FileNodeV2:
    guest_path: str
    served_path: str
    size: int
    sha256: str
    metadata: NodeMetadataV2

    def __post_init__(self) -> None:
        _text(self.guest_path, "file.guest_path", printable_ascii=True)
        _validate_served_path(self.served_path)
        _integer(
            self.size,
            f"file {self.served_path!r} size",
            maximum=resources.RESOURCE_POLICY.max_file_bytes,
        )
        _labelled_sha256(self.sha256, f"file {self.served_path!r} sha256")
        if not isinstance(
            self.metadata,
            (LinuxMetadataV2, MacOSMetadataV2, WindowsMetadataV2),
        ):
            raise FixtureV2ValidationError("file.metadata has an unsupported type")

    @classmethod
    def from_bytes(
        cls,
        *,
        guest_path: str,
        served_path: str,
        data: bytes,
        metadata: NodeMetadataV2,
    ) -> FileNodeV2:
        if not isinstance(data, bytes):
            raise TypeError("file node data must be bytes")
        return cls(
            guest_path=guest_path,
            served_path=served_path,
            size=len(data),
            sha256="sha256:" + hashlib.sha256(data).hexdigest(),
            metadata=metadata,
        )

    @classmethod
    def from_mapping(
        cls,
        value: object,
        *,
        family: str,
        where: str,
    ) -> FileNodeV2:
        mapping = _as_mapping(value, where)
        _exact_keys(
            mapping,
            {"guest_path", "served_path", "size", "sha256", "metadata"},
            where,
        )
        return cls(
            guest_path=_text(
                mapping["guest_path"], f"{where}.guest_path", printable_ascii=True
            ),
            served_path=_validate_served_path(mapping["served_path"]),
            size=_integer(
                mapping["size"],
                f"{where}.size",
                maximum=resources.RESOURCE_POLICY.max_file_bytes,
            ),
            sha256=_labelled_sha256(mapping["sha256"], f"{where}.sha256"),
            metadata=_metadata_from_mapping(
                mapping["metadata"], family=family, where=f"{where}.metadata"
            ),
        )

    def to_mapping(self) -> dict[str, JSONValue]:
        return {
            "guest_path": self.guest_path,
            "served_path": self.served_path,
            "size": self.size,
            "sha256": self.sha256,
            "metadata": self.metadata.to_mapping(),
        }


def _metadata_blobs(metadata: NodeMetadataV2) -> tuple[NamedBlobV2, ...]:
    if type(metadata) is MacOSMetadataV2:
        return metadata.xattrs
    if type(metadata) is WindowsMetadataV2:
        return metadata.streams
    return ()


def _bounded_directories(
    directories: Iterable[DirectoryNodeV2],
) -> tuple[DirectoryNodeV2, ...]:
    raw = _bounded_values(
        directories,
        maximum=MAX_V2_DIRECTORIES,
        where="payload.directories",
    )
    result: list[DirectoryNodeV2] = []
    for index, node in enumerate(raw):
        if type(node) is not DirectoryNodeV2:
            raise FixtureV2ValidationError(
                f"payload.directories[{index}] must be a DirectoryNodeV2"
            )
        result.append(node)
    return tuple(result)


def _bounded_files(files: Iterable[FileNodeV2]) -> tuple[FileNodeV2, ...]:
    raw = _bounded_values(files, maximum=MAX_V2_FILES, where="payload.files")
    result: list[FileNodeV2] = []
    for index, node in enumerate(raw):
        if type(node) is not FileNodeV2:
            raise FixtureV2ValidationError(f"payload.files[{index}] must be a FileNodeV2")
        result.append(node)
    if not result:
        raise FixtureV2ValidationError("payload.files must contain at least one file")
    return tuple(result)


def _validate_node_collection(
    *,
    family: str,
    directories: Iterable[DirectoryNodeV2],
    files: Iterable[FileNodeV2],
    require_sorted: bool,
) -> tuple[
    tuple[DirectoryNodeV2, ...],
    tuple[FileNodeV2, ...],
    int,
    int,
    int,
]:
    if family not in {"windows", "macos", "linux"}:
        raise FixtureV2ValidationError("payload.family must be windows, macos or linux")
    supplied_directories = _bounded_directories(directories)
    supplied_files = _bounded_files(files)
    if len(supplied_directories) + len(supplied_files) > MAX_V2_NODES:
        raise FixtureV2ValidationError(
            f"payload tree exceeds the {MAX_V2_NODES}-node limit"
        )
    ordered_directories = tuple(
        sorted(supplied_directories, key=lambda node: node.served_path)
    )
    ordered_files = tuple(sorted(supplied_files, key=lambda node: node.served_path))
    if require_sorted and supplied_directories != ordered_directories:
        raise FixtureV2ValidationError("payload.directories must be sorted by served_path")
    if require_sorted and supplied_files != ordered_files:
        raise FixtureV2ValidationError("payload.files must be sorted by served_path")

    full_paths: dict[str, str] = {}
    folded_paths: dict[str, str] = {}
    folded_prefixes: dict[str, str] = {}
    guest_paths: dict[str, str] = {}
    metadata_blob_count = 0
    metadata_blob_bytes = 0

    for kind, nodes in (("directory", ordered_directories), ("file", ordered_files)):
        for index, node in enumerate(nodes):
            where = f"payload.{kind}s[{index}]"
            expected_served = guest_path_to_served_path(family, node.guest_path)
            if node.served_path != expected_served:
                raise FixtureV2ValidationError(
                    f"{where}.served_path must be {expected_served!r} for its guest path"
                )
            if served_path_to_guest_path(family, node.served_path) != node.guest_path:
                raise FixtureV2ValidationError(f"{where} guest/served mapping is not reversible")
            if (
                family == "windows"
                and kind == "file"
                and len(node.served_path) == 1
                and node.served_path in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            ):
                raise FixtureV2ValidationError(
                    f"{where} cannot model Windows drive root {node.guest_path!r} "
                    "as a file; drive roots can only be directories"
                )
            _validate_node_metadata(node.metadata, family=family, kind=kind, where=where)

            previous_kind = full_paths.get(node.served_path)
            if previous_kind is not None:
                raise FixtureV2ValidationError(
                    f"payload path {node.served_path!r} is a duplicate or both "
                    f"{previous_kind} and {kind}"
                )
            full_paths[node.served_path] = kind
            folded = node.served_path.casefold()
            previous_path = folded_paths.get(folded)
            if previous_path is not None and previous_path != node.served_path:
                raise FixtureV2ValidationError(
                    f"case-folding served path collision: {previous_path!r} and "
                    f"{node.served_path!r}"
                )
            folded_paths[folded] = node.served_path

            guest_folded = node.guest_path.casefold()
            previous_guest = guest_paths.get(guest_folded)
            if previous_guest is not None and previous_guest != node.guest_path:
                raise FixtureV2ValidationError(
                    f"case-folding guest path collision: {previous_guest!r} and "
                    f"{node.guest_path!r}"
                )
            guest_paths[guest_folded] = node.guest_path

            parts = node.served_path.split("/")
            for part_index in range(1, len(parts) + 1):
                prefix = "/".join(parts[:part_index])
                prefix_folded = prefix.casefold()
                previous_prefix = folded_prefixes.get(prefix_folded)
                if previous_prefix is not None and previous_prefix != prefix:
                    raise FixtureV2ValidationError(
                        f"case-folding path-prefix collision: {previous_prefix!r} and "
                        f"{prefix!r}"
                    )
                folded_prefixes[prefix_folded] = prefix

            blobs = _metadata_blobs(node.metadata)
            metadata_blob_count += len(blobs)
            metadata_blob_bytes += sum(blob.size for blob in blobs)
            if metadata_blob_count > MAX_V2_METADATA_BLOBS:
                raise FixtureV2ValidationError(
                    f"payload metadata exceeds the {MAX_V2_METADATA_BLOBS}-blob limit"
                )
            if metadata_blob_bytes > MAX_V2_METADATA_BLOB_BYTES:
                raise FixtureV2ValidationError(
                    "payload metadata blobs exceed the "
                    f"{MAX_V2_METADATA_BLOB_BYTES}-byte aggregate limit"
                )

    directory_paths = {node.served_path for node in ordered_directories}
    for kind, nodes in (("directory", ordered_directories), ("file", ordered_files)):
        for node in nodes:
            parts = node.served_path.split("/")
            for part_index in range(1, len(parts)):
                parent = "/".join(parts[:part_index])
                if parent not in directory_paths:
                    raise FixtureV2ValidationError(
                        f"payload {kind} {node.served_path!r} is missing explicit "
                        f"parent directory {parent!r}"
                    )

    required_directories = {
        "/".join(parts[:part_index])
        for node in ordered_files
        for parts in (node.served_path.split("/"),)
        for part_index in range(1, len(parts))
    }
    orphaned = sorted(directory_paths - required_directories)
    if orphaned:
        raise FixtureV2ValidationError(
            "payload directories must each be an ancestor of a file; orphaned: "
            + ", ".join(repr(path) for path in orphaned)
        )

    regular_file_bytes = sum(node.size for node in ordered_files)
    total_bound_bytes = regular_file_bytes + metadata_blob_bytes
    if total_bound_bytes > MAX_V2_BOUND_BYTES:
        raise FixtureV2ValidationError(
            f"payload bytes exceed the {MAX_V2_BOUND_BYTES}-byte total bound"
        )
    return (
        ordered_directories,
        ordered_files,
        regular_file_bytes,
        metadata_blob_count,
        metadata_blob_bytes,
    )


def canonical_nodes_v2(
    *,
    family: str,
    directories: Iterable[DirectoryNodeV2],
    files: Iterable[FileNodeV2],
) -> tuple[tuple[DirectoryNodeV2, ...], tuple[FileNodeV2, ...]]:
    """Validate one complete logical tree and return its two canonical node orders."""
    validated = _validate_node_collection(
        family=family,
        directories=directories,
        files=files,
        require_sorted=False,
    )
    return validated[0], validated[1]


def _tree_digest_from_validated(
    *,
    family: str,
    directories: tuple[DirectoryNodeV2, ...],
    files: tuple[FileNodeV2, ...],
) -> str:
    digest_input = {
        "canonicalization": TREE_CANONICALIZATION_V2,
        "family": family,
        "directories": [node.to_mapping() for node in directories],
        "files": [node.to_mapping() for node in files],
    }
    return _domain_sha256(TREE_DIGEST_DOMAIN_V2, digest_input)


def compute_tree_sha256_v2(
    *,
    family: str,
    directories: Iterable[DirectoryNodeV2],
    files: Iterable[FileNodeV2],
) -> str:
    """Hash every canonical v2 node, logical metadata value, and byte identity."""
    ordered_directories, ordered_files, *_ = _validate_node_collection(
        family=family,
        directories=directories,
        files=files,
        require_sorted=False,
    )
    return _tree_digest_from_validated(
        family=family,
        directories=ordered_directories,
        files=ordered_files,
    )


@dataclass(frozen=True)
class FixturePurposeV2:
    kind: str = SPEC_PURPOSE_V2
    benchmark_eligible: bool = False

    def __post_init__(self) -> None:
        _constant(self.kind, SPEC_PURPOSE_V2, "manifest.purpose.kind")
        _constant(self.benchmark_eligible, False, "manifest.purpose.benchmark_eligible")

    @classmethod
    def from_mapping(cls, value: object) -> FixturePurposeV2:
        mapping = _as_mapping(value, "manifest.purpose")
        _exact_keys(mapping, {"kind", "benchmark_eligible"}, "manifest.purpose")
        return cls(
            kind=_text(mapping["kind"], "manifest.purpose.kind", printable_ascii=True),
            benchmark_eligible=mapping["benchmark_eligible"],
        )

    def to_mapping(self) -> dict[str, JSONValue]:
        return {"kind": self.kind, "benchmark_eligible": self.benchmark_eligible}


@dataclass(frozen=True)
class GeneratorIdentityV2:
    version: str
    name: str = GENERATOR_NAME_V2
    abi: str = GENERATOR_ABI_V2
    producer_profile: str = PRODUCER_PROFILE_V2

    def __post_init__(self) -> None:
        _constant(self.name, GENERATOR_NAME_V2, "manifest.generator.name")
        version = _text(self.version, "manifest.generator.version", printable_ascii=True)
        if len(version.encode("ascii")) > MAX_V2_GENERATOR_VERSION_BYTES:
            raise FixtureV2ValidationError(
                "manifest.generator.version exceeds the "
                f"{MAX_V2_GENERATOR_VERSION_BYTES}-byte limit"
            )
        _constant(self.abi, GENERATOR_ABI_V2, "manifest.generator.abi")
        _constant(
            self.producer_profile,
            PRODUCER_PROFILE_V2,
            "manifest.generator.producer_profile",
        )

    @classmethod
    def from_mapping(cls, value: object) -> GeneratorIdentityV2:
        mapping = _as_mapping(value, "manifest.generator")
        _exact_keys(
            mapping,
            {"name", "version", "abi", "producer_profile"},
            "manifest.generator",
        )
        return cls(
            name=_text(mapping["name"], "manifest.generator.name", printable_ascii=True),
            version=_text(
                mapping["version"], "manifest.generator.version", printable_ascii=True
            ),
            abi=_text(mapping["abi"], "manifest.generator.abi", printable_ascii=True),
            producer_profile=_text(
                mapping["producer_profile"],
                "manifest.generator.producer_profile",
                printable_ascii=True,
            ),
        )

    def to_mapping(self) -> dict[str, JSONValue]:
        return {
            "name": self.name,
            "version": self.version,
            "abi": self.abi,
            "producer_profile": self.producer_profile,
        }


@dataclass(frozen=True)
class FixturePayloadV2:
    family: str
    directory_count: int
    file_count: int
    regular_file_bytes: int
    metadata_blob_count: int
    metadata_blob_bytes: int
    total_bound_bytes: int
    tree_sha256: str
    directories: tuple[DirectoryNodeV2, ...]
    files: tuple[FileNodeV2, ...]
    root: str = PAYLOAD_ROOT_V2
    canonicalization: str = TREE_CANONICALIZATION_V2
    digest_domain: str = TREE_DIGEST_DOMAIN_V2

    def __post_init__(self) -> None:
        _constant(self.root, PAYLOAD_ROOT_V2, "manifest.payload.root")
        _constant(
            self.canonicalization,
            TREE_CANONICALIZATION_V2,
            "manifest.payload.canonicalization",
        )
        _constant(
            self.digest_domain,
            TREE_DIGEST_DOMAIN_V2,
            "manifest.payload.digest_domain",
        )
        family = _text(self.family, "manifest.payload.family", printable_ascii=True)
        validated = _validate_node_collection(
            family=family,
            directories=self.directories,
            files=self.files,
            require_sorted=True,
        )
        directories, files, regular_bytes, blob_count, blob_bytes = validated
        object.__setattr__(self, "directories", directories)
        object.__setattr__(self, "files", files)

        equations = (
            ("directory_count", self.directory_count, len(directories), MAX_V2_DIRECTORIES),
            ("file_count", self.file_count, len(files), MAX_V2_FILES),
            ("regular_file_bytes", self.regular_file_bytes, regular_bytes, MAX_V2_BOUND_BYTES),
            ("metadata_blob_count", self.metadata_blob_count, blob_count, MAX_V2_METADATA_BLOBS),
            (
                "metadata_blob_bytes",
                self.metadata_blob_bytes,
                blob_bytes,
                MAX_V2_METADATA_BLOB_BYTES,
            ),
            (
                "total_bound_bytes",
                self.total_bound_bytes,
                regular_bytes + blob_bytes,
                MAX_V2_BOUND_BYTES,
            ),
        )
        for name, supplied, expected, maximum in equations:
            _integer(supplied, f"manifest.payload.{name}", maximum=maximum)
            if supplied != expected:
                raise FixtureV2ValidationError(
                    f"manifest.payload.{name} does not equal derived value {expected}"
                )

        tree_sha256 = _labelled_sha256(
            self.tree_sha256, "manifest.payload.tree_sha256"
        )
        expected_tree = _tree_digest_from_validated(
            family=family,
            directories=directories,
            files=files,
        )
        if tree_sha256 != expected_tree:
            raise FixtureV2ValidationError(
                f"manifest.payload.tree_sha256 mismatch: expected {expected_tree}"
            )

    @classmethod
    def create(
        cls,
        *,
        family: str,
        directories: Iterable[DirectoryNodeV2],
        files: Iterable[FileNodeV2],
    ) -> FixturePayloadV2:
        validated = _validate_node_collection(
            family=family,
            directories=directories,
            files=files,
            require_sorted=False,
        )
        ordered_directories, ordered_files, regular_bytes, blob_count, blob_bytes = validated
        return cls(
            family=family,
            directory_count=len(ordered_directories),
            file_count=len(ordered_files),
            regular_file_bytes=regular_bytes,
            metadata_blob_count=blob_count,
            metadata_blob_bytes=blob_bytes,
            total_bound_bytes=regular_bytes + blob_bytes,
            tree_sha256=_tree_digest_from_validated(
                family=family,
                directories=ordered_directories,
                files=ordered_files,
            ),
            directories=ordered_directories,
            files=ordered_files,
        )

    @classmethod
    def from_mapping(cls, value: object) -> FixturePayloadV2:
        mapping = _as_mapping(value, "manifest.payload")
        _exact_keys(
            mapping,
            {
                "root",
                "family",
                "canonicalization",
                "digest_domain",
                "directory_count",
                "file_count",
                "regular_file_bytes",
                "metadata_blob_count",
                "metadata_blob_bytes",
                "total_bound_bytes",
                "tree_sha256",
                "directories",
                "files",
            },
            "manifest.payload",
        )
        family = _text(mapping["family"], "manifest.payload.family", printable_ascii=True)
        raw_directories = mapping["directories"]
        raw_files = mapping["files"]
        if not isinstance(raw_directories, list):
            raise FixtureV2ValidationError("manifest.payload.directories must be an array")
        if not isinstance(raw_files, list):
            raise FixtureV2ValidationError("manifest.payload.files must be an array")
        if len(raw_directories) > MAX_V2_DIRECTORIES:
            raise FixtureV2ValidationError(
                "manifest.payload.directories exceeds the "
                f"{MAX_V2_DIRECTORIES}-directory limit"
            )
        if len(raw_files) > MAX_V2_FILES:
            raise FixtureV2ValidationError(
                f"manifest.payload.files exceeds the {MAX_V2_FILES}-file limit"
            )
        return cls(
            root=_text(mapping["root"], "manifest.payload.root", printable_ascii=True),
            family=family,
            canonicalization=_text(
                mapping["canonicalization"],
                "manifest.payload.canonicalization",
                printable_ascii=True,
            ),
            digest_domain=_text(
                mapping["digest_domain"],
                "manifest.payload.digest_domain",
                printable_ascii=True,
            ),
            directory_count=_integer(
                mapping["directory_count"],
                "manifest.payload.directory_count",
                maximum=MAX_V2_DIRECTORIES,
            ),
            file_count=_integer(
                mapping["file_count"],
                "manifest.payload.file_count",
                maximum=MAX_V2_FILES,
            ),
            regular_file_bytes=_integer(
                mapping["regular_file_bytes"],
                "manifest.payload.regular_file_bytes",
                maximum=MAX_V2_BOUND_BYTES,
            ),
            metadata_blob_count=_integer(
                mapping["metadata_blob_count"],
                "manifest.payload.metadata_blob_count",
                maximum=MAX_V2_METADATA_BLOBS,
            ),
            metadata_blob_bytes=_integer(
                mapping["metadata_blob_bytes"],
                "manifest.payload.metadata_blob_bytes",
                maximum=MAX_V2_METADATA_BLOB_BYTES,
            ),
            total_bound_bytes=_integer(
                mapping["total_bound_bytes"],
                "manifest.payload.total_bound_bytes",
                maximum=MAX_V2_BOUND_BYTES,
            ),
            tree_sha256=_labelled_sha256(
                mapping["tree_sha256"], "manifest.payload.tree_sha256"
            ),
            directories=tuple(
                DirectoryNodeV2.from_mapping(
                    item,
                    family=family,
                    where=f"manifest.payload.directories[{index}]",
                )
                for index, item in enumerate(raw_directories)
            ),
            files=tuple(
                FileNodeV2.from_mapping(
                    item,
                    family=family,
                    where=f"manifest.payload.files[{index}]",
                )
                for index, item in enumerate(raw_files)
            ),
        )

    def to_mapping(self) -> dict[str, JSONValue]:
        return {
            "root": self.root,
            "family": self.family,
            "canonicalization": self.canonicalization,
            "digest_domain": self.digest_domain,
            "directory_count": self.directory_count,
            "file_count": self.file_count,
            "regular_file_bytes": self.regular_file_bytes,
            "metadata_blob_count": self.metadata_blob_count,
            "metadata_blob_bytes": self.metadata_blob_bytes,
            "total_bound_bytes": self.total_bound_bytes,
            "tree_sha256": self.tree_sha256,
            "directories": [node.to_mapping() for node in self.directories],
            "files": [node.to_mapping() for node in self.files],
        }


@dataclass(frozen=True)
class FixtureManifestV2:
    generator: GeneratorIdentityV2
    recipe: FixtureSpecV2
    recipe_sha256: str
    payload: FixturePayloadV2
    schema: str = MANIFEST_SCHEMA_V2
    canonicalization: str = CANONICALIZATION_V1
    recipe_digest_domain: str = RECIPE_DIGEST_DOMAIN_V2
    purpose: FixturePurposeV2 = FixturePurposeV2()

    def __post_init__(self) -> None:
        _constant(self.schema, MANIFEST_SCHEMA_V2, "manifest.schema")
        _constant(
            self.canonicalization,
            CANONICALIZATION_V1,
            "manifest.canonicalization",
        )
        _constant(
            self.recipe_digest_domain,
            RECIPE_DIGEST_DOMAIN_V2,
            "manifest.recipe_digest_domain",
        )
        if type(self.purpose) is not FixturePurposeV2:
            raise FixtureV2ValidationError("manifest.purpose must be a FixturePurposeV2")
        if type(self.generator) is not GeneratorIdentityV2:
            raise FixtureV2ValidationError(
                "manifest.generator must be a GeneratorIdentityV2"
            )
        if type(self.recipe) is not FixtureSpecV2:
            raise FixtureV2ValidationError("manifest.recipe must be a FixtureSpecV2")
        if type(self.payload) is not FixturePayloadV2:
            raise FixtureV2ValidationError("manifest.payload must be a FixturePayloadV2")
        if self.payload.family != self.recipe.family:
            raise FixtureV2ValidationError(
                "manifest.payload.family must equal manifest.recipe.family"
            )
        archive_root = self.recipe.fixture_id + "/"
        archive_names = (
            archive_root,
            archive_root + "fixture.json",
            archive_root + PAYLOAD_ROOT_V2 + "/",
            *(
                archive_root + PAYLOAD_ROOT_V2 + "/" + node.served_path + "/"
                for node in self.payload.directories
            ),
            *(
                archive_root + PAYLOAD_ROOT_V2 + "/" + node.served_path
                for node in self.payload.files
            ),
        )
        for archive_name in archive_names:
            validate_ustar_member_name_v2(archive_name)
        recipe_sha256 = _labelled_sha256(
            self.recipe_sha256, "manifest.recipe_sha256"
        )
        if recipe_sha256 != self.recipe.recipe_sha256:
            raise FixtureV2ValidationError(
                f"manifest.recipe_sha256 mismatch: expected {self.recipe.recipe_sha256}"
            )

    @classmethod
    def create(
        cls,
        *,
        generator_version: str,
        recipe: FixtureSpecV2,
        payload: FixturePayloadV2,
    ) -> FixtureManifestV2:
        """Construct a typed record; producer availability remains an ABI-registry decision."""
        return cls(
            generator=GeneratorIdentityV2(version=generator_version),
            recipe=recipe,
            recipe_sha256=recipe.recipe_sha256,
            payload=payload,
        )

    @classmethod
    def from_mapping(cls, value: object) -> FixtureManifestV2:
        mapping = _as_mapping(value, "manifest")
        _exact_keys(
            mapping,
            {
                "schema",
                "canonicalization",
                "recipe_digest_domain",
                "purpose",
                "generator",
                "recipe",
                "recipe_sha256",
                "payload",
            },
            "manifest",
        )
        return cls(
            schema=_text(mapping["schema"], "manifest.schema", printable_ascii=True),
            canonicalization=_text(
                mapping["canonicalization"],
                "manifest.canonicalization",
                printable_ascii=True,
            ),
            recipe_digest_domain=_text(
                mapping["recipe_digest_domain"],
                "manifest.recipe_digest_domain",
                printable_ascii=True,
            ),
            purpose=FixturePurposeV2.from_mapping(mapping["purpose"]),
            generator=GeneratorIdentityV2.from_mapping(mapping["generator"]),
            recipe=FixtureSpecV2.from_mapping(mapping["recipe"]),
            recipe_sha256=_labelled_sha256(
                mapping["recipe_sha256"], "manifest.recipe_sha256"
            ),
            payload=FixturePayloadV2.from_mapping(mapping["payload"]),
        )

    @classmethod
    def from_json(cls, data: bytes | str) -> FixtureManifestV2:
        return cls.from_mapping(load_json_strict(data))

    @classmethod
    def from_canonical_json(cls, data: bytes) -> FixtureManifestV2:
        return cls.from_mapping(load_canonical_json(data))

    def to_mapping(self) -> dict[str, JSONValue]:
        return {
            "schema": self.schema,
            "canonicalization": self.canonicalization,
            "recipe_digest_domain": self.recipe_digest_domain,
            "purpose": self.purpose.to_mapping(),
            "generator": self.generator.to_mapping(),
            "recipe": self.recipe.to_mapping(),
            "recipe_sha256": self.recipe_sha256,
            "payload": self.payload.to_mapping(),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_mapping())


__all__ = [
    "CLOCK_CONTEXT_DOMAIN_V2",
    "CONTENT_STORE_NAMESPACE_V2",
    "DirectoryNodeV2",
    "FileNodeV2",
    "FixtureManifestV2",
    "FixturePayloadV2",
    "FixturePurposeV2",
    "FixtureSpecV2",
    "FixtureV2ValidationError",
    "GeneratorIdentityV2",
    "LINUX_METADATA_SCHEMA_V2",
    "LinuxMetadataV2",
    "MACOS_METADATA_SCHEMA_V2",
    "MAX_V2_BLOBS_PER_NODE",
    "MAX_V2_BLOB_BYTES",
    "MAX_V2_BLOB_NAME_BYTES",
    "MAX_V2_BOUND_BYTES",
    "MAX_V2_DIRECTORIES",
    "MAX_V2_FILES",
    "MAX_V2_GUEST_PATH_BYTES",
    "MAX_V2_GENERATOR_VERSION_BYTES",
    "MAX_V2_METADATA_BLOB_BYTES",
    "MAX_V2_PATH_SEGMENTS",
    "MAX_V2_SERVED_PATH_BYTES",
    "MacOSMetadataV2",
    "NamedBlobV2",
    "NodeMetadataV2",
    "PROFILE_FAMILIES_V2",
    "ProfileSpecV2",
    "RECIPE_DIGEST_DOMAIN_V2",
    "SCENE_KEY_DOMAIN_V2",
    "TREE_DIGEST_DOMAIN_V2",
    "WINDOWS_ATTRIBUTES_V2",
    "WINDOWS_METADATA_SCHEMA_V2",
    "WindowsMetadataV2",
    "canonical_nodes_v2",
    "compute_recipe_sha256_v2",
    "compute_tree_sha256_v2",
    "guest_path_to_served_path",
    "served_path_to_guest_path",
    "validate_ustar_member_name_v2",
]
