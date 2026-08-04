# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Type-exact external-parser observations for the bounded Shell Link profile.

``liblnk-python`` and ``LnkParse3`` expose different interfaces and have different failure
modes.  The adapters below deliberately use only their public decoded surfaces.  liblnk
provides exact integer FILETIMEs but does not expose a consumed-byte count; LnkParse3 exposes
its consumed size but converts FILETIMEs through :class:`datetime.datetime`.  Requiring the
two frozen observations to agree catches that loss of precision instead of silently rounding
it away.

These functions establish independent parser extraction and consensus.  The first-party
reader in :mod:`artifactforge.artifacts.shell_link` separately owns byte-layout constraints
that neither external library fully exposes, including the exact terminal block and both
common-suffix extents.

Both third-party imports are lazy.  They remain development/CI oracles and never become
dependencies of ArtifactForge's zero-dependency generator.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import io
import re
import unicodedata
import warnings

from artifactforge.disclosure import MARKER


MAX_SHELL_LINK_ORACLE_BYTES = 4096
_MIN_SHELL_LINK_BYTES = 77
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_MIN_PORTABLE_FILETIME = 116_444_736_000_000_000
_MAX_PORTABLE_FILETIME = 202_344_081_920_000_000
_MARKED_NAME_SUFFIX = f" [{MARKER} SYNTHETIC]"
_INVALID_PATH_CHARACTERS = frozenset('<>:"/|?*')
_INVALID_LABEL_CHARACTERS = frozenset('\\/:*?"<>|')
_RESERVED_COMPONENT = re.compile(
    r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", re.IGNORECASE
)


class ShellLinkOracleError(ValueError):
    """An external parser observation is missing, malformed, or inconsistent."""


@dataclass(frozen=True)
class ShellLinkOracleView:
    """The semantic intersection exposed by liblnk and LnkParse3."""

    target_path: str
    description: str
    target_size: int
    creation_filetime: int
    access_filetime: int
    write_filetime: int
    volume_serial: int
    volume_label: str
    drive_type: int
    link_flags: int
    file_attribute_flags: int
    icon_index: int
    show_window_value: int
    hot_key_value: int
    optional_surfaces: tuple[str, ...]
    data_block_count: int

    def detail(self) -> str:
        return (
            f"target={self.target_path},size={self.target_size},"
            f"volume={self.volume_label}/{self.volume_serial:08x},"
            f"flags={self.link_flags:#x},blocks={self.data_block_count}"
        )


def _input_bytes(data: object) -> bytes:
    if type(data) is not bytes:
        raise ShellLinkOracleError("Shell Link oracle input must be immutable bytes")
    if not _MIN_SHELL_LINK_BYTES <= len(data) <= MAX_SHELL_LINK_ORACLE_BYTES:
        raise ShellLinkOracleError(
            f"Shell Link oracle input must contain {_MIN_SHELL_LINK_BYTES}.."
            f"{MAX_SHELL_LINK_ORACLE_BYTES} bytes"
        )
    return data


def _integer(value: object, *, bits: int, where: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ShellLinkOracleError(f"{where} is not an unsigned {bits}-bit integer")
    return value


def _signed_integer(value: object, *, bits: int, where: str) -> int:
    if type(value) is not int or not -(1 << (bits - 1)) <= value < 1 << (bits - 1):
        raise ShellLinkOracleError(f"{where} is not a signed {bits}-bit integer")
    return value


def _text(value: object, *, where: str, allow_empty: bool = False) -> str:
    if type(value) is not str or "\x00" in value or (not allow_empty and not value):
        qualifier = "NUL-free text" if allow_empty else "non-empty NUL-free text"
        raise ShellLinkOracleError(f"{where} is not {qualifier}")
    return value


def _filetime_from_datetime(value: object, *, where: str) -> int:
    if value is None:
        return 0
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ShellLinkOracleError(f"{where} is not an aware datetime or None")
    utc = value.astimezone(timezone.utc)
    delta = utc - _FILETIME_EPOCH
    microseconds = (
        (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds
    )
    return _integer(microseconds * 10, bits=64, where=f"{where} converted FILETIME")


def _optional_surface(values: Mapping[str, object]) -> tuple[str, ...]:
    return tuple(sorted(name for name, value in values.items() if value is not None))


def liblnk_shell_link_view(data: bytes) -> ShellLinkOracleView:
    """Parse one bounded byte string through libyal's ``pylnk`` binding."""
    data = _input_bytes(data)
    import pylnk

    try:
        parsed = pylnk.open_file_object(io.BytesIO(data))
    except (OSError, TypeError, ValueError) as exc:
        raise ShellLinkOracleError(f"liblnk rejected Shell Link: {exc}") from exc

    try:
        corrupted = parsed.is_corrupted()
        if type(corrupted) is not bool or corrupted:
            raise ShellLinkOracleError("liblnk reports a corrupt or indeterminate Shell Link")

        optional_values = {
            "arguments": parsed.get_command_line_arguments(),
            "environment": parsed.get_environment_variables_location(),
            "icon-location": parsed.get_icon_location(),
            "network-path": parsed.get_network_path(),
            "relative-path": parsed.get_relative_path(),
            "target-id-list": parsed.get_link_target_identifier_data(),
            "working-directory": parsed.get_working_directory(),
        }
        view = ShellLinkOracleView(
            target_path=_text(parsed.get_local_path(), where="liblnk local path"),
            description=_text(parsed.get_description(), where="liblnk description"),
            target_size=_integer(
                parsed.get_file_size(), bits=32, where="liblnk target size"
            ),
            creation_filetime=_integer(
                parsed.get_file_creation_time_as_integer(),
                bits=64,
                where="liblnk creation FILETIME",
            ),
            access_filetime=_integer(
                parsed.get_file_access_time_as_integer(),
                bits=64,
                where="liblnk access FILETIME",
            ),
            write_filetime=_integer(
                parsed.get_file_modification_time_as_integer(),
                bits=64,
                where="liblnk write FILETIME",
            ),
            volume_serial=_integer(
                parsed.get_drive_serial_number(), bits=32, where="liblnk volume serial"
            ),
            volume_label=_text(parsed.get_volume_label(), where="liblnk volume label"),
            drive_type=_integer(parsed.get_drive_type(), bits=32, where="liblnk drive type"),
            link_flags=_integer(parsed.get_data_flags(), bits=32, where="liblnk link flags"),
            file_attribute_flags=_integer(
                parsed.get_file_attribute_flags(),
                bits=32,
                where="liblnk file-attribute flags",
            ),
            icon_index=_signed_integer(
                parsed.get_icon_index(), bits=32, where="liblnk icon index"
            ),
            show_window_value=_integer(
                parsed.get_show_window_value(), bits=32, where="liblnk show-window value"
            ),
            hot_key_value=_integer(
                parsed.get_hot_key_value(), bits=16, where="liblnk hot-key value"
            ),
            optional_surfaces=_optional_surface(optional_values),
            data_block_count=_integer(
                parsed.get_number_of_data_blocks(),
                bits=32,
                where="liblnk ExtraData block count",
            ),
        )
    except ShellLinkOracleError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise ShellLinkOracleError(f"liblnk could not extract Shell Link semantics: {exc}") from exc
    finally:
        parsed.close()
    return view


def _lnkparse3_serial(value: object) -> int:
    if type(value) is not str or re.fullmatch(r"0x[0-9a-f]+", value) is None:
        raise ShellLinkOracleError("LnkParse3 volume serial is not canonical hexadecimal text")
    return _integer(int(value, 16), bits=32, where="LnkParse3 volume serial")


def _lnkparse3_window_value(value: object) -> int:
    values = {"SW_SHOWNORMAL": 1, "SW_SHOWMAXIMIZED": 3, "SW_SHOWMINNOACTIVE": 7}
    if type(value) is not str or value not in values:
        raise ShellLinkOracleError("LnkParse3 window style is outside its decoded enum")
    return values[value]


def lnkparse3_shell_link_view(data: bytes) -> ShellLinkOracleView:
    """Parse one bounded byte string through LnkParse3 with fail-closed warnings."""
    data = _input_bytes(data)
    from LnkParse3.lnk_file import LnkFile

    observed_warnings: list[warnings.WarningMessage]
    try:
        with warnings.catch_warnings(record=True) as observed_warnings:
            warnings.simplefilter("always")
            parsed = LnkFile(indata=data, allow_terminal_blocks=True)
            header = parsed.header
            info = parsed.info
            if info is None or info.location() != "Local":
                raise ShellLinkOracleError("LnkParse3 did not decode one local LinkInfo")
            if type(parsed.size) is not int or parsed.size != len(data):
                raise ShellLinkOracleError(
                    f"LnkParse3 consumed {parsed.size!r} of {len(data)} Shell Link bytes"
                )
            if list(parsed.extras) or parsed.extras.as_dict():
                raise ShellLinkOracleError(
                    "LnkParse3 observed ExtraData or bytes appended to the terminal block"
                )
            if header.size() != 0x4C or header.link_cls_id() != (
                "00021401-0000-0000-C000-000000000046"
            ):
                raise ShellLinkOracleError("LnkParse3 header size or CLSID is not canonical")
            if any((header.reserved0(), header.reserved1(), header.reserved2())):
                raise ShellLinkOracleError("LnkParse3 observed non-zero reserved header fields")
            if (
                info.header_size() != 0x24
                or info.flags() != 1
                or info.volume_id_offset() != 0x24
                or info.common_network_relative_link_offset() != 0
            ):
                raise ShellLinkOracleError("LnkParse3 LinkInfo is outside the local 0x24 profile")
            target_path = _text(info.local_base_path(), where="LnkParse3 ANSI local path")
            unicode_path = _text(
                info.local_base_path_unicode(), where="LnkParse3 Unicode local path"
            )
            if target_path != unicode_path:
                raise ShellLinkOracleError(
                    "LnkParse3 ANSI and Unicode local-path observations disagree"
                )
            if info.common_path_suffix() != "":
                raise ShellLinkOracleError("LnkParse3 ANSI common path suffix is not empty")
            if (
                info.r_drive_type() != 3
                or info.volume_label_offset() != 16
                or info.volume_label_unicode_offset() is not None
            ):
                raise ShellLinkOracleError("LnkParse3 VolumeID is outside the ANSI fixed profile")

            string_data = parsed.string_data.as_dict()
            if type(string_data) is not dict or set(string_data) != {"description"}:
                raise ShellLinkOracleError(
                    "LnkParse3 StringData does not contain exactly one description"
                )
            optional_values = {
                "arguments": parsed.string_data.command_line_arguments(),
                "icon-location": parsed.string_data.icon_location(),
                "relative-path": parsed.string_data.relative_path(),
                "target-id-list": parsed.targets,
                "working-directory": parsed.string_data.working_directory(),
            }
            view = ShellLinkOracleView(
                target_path=target_path,
                description=_text(
                    string_data["description"], where="LnkParse3 description"
                ),
                target_size=_integer(
                    header.file_size(), bits=32, where="LnkParse3 target size"
                ),
                creation_filetime=_filetime_from_datetime(
                    header.creation_time(), where="LnkParse3 creation time"
                ),
                access_filetime=_filetime_from_datetime(
                    header.access_time(), where="LnkParse3 access time"
                ),
                write_filetime=_filetime_from_datetime(
                    header.write_time(), where="LnkParse3 write time"
                ),
                volume_serial=_lnkparse3_serial(info.drive_serial_number()),
                volume_label=_text(info.volume_label(), where="LnkParse3 volume label"),
                drive_type=_integer(
                    info.r_drive_type(), bits=32, where="LnkParse3 drive type"
                ),
                link_flags=_integer(
                    header.r_link_flags(), bits=32, where="LnkParse3 link flags"
                ),
                file_attribute_flags=_integer(
                    header.r_file_flags(), bits=32, where="LnkParse3 file-attribute flags"
                ),
                icon_index=_signed_integer(
                    header.icon_index(), bits=32, where="LnkParse3 icon index"
                ),
                show_window_value=_lnkparse3_window_value(header.window_style()),
                hot_key_value=_integer(
                    header.raw_hot_key(), bits=16, where="LnkParse3 hot-key value"
                ),
                optional_surfaces=_optional_surface(optional_values),
                data_block_count=0,
            )
    except ShellLinkOracleError:
        raise
    except (IndexError, KeyError, OSError, TypeError, ValueError) as exc:
        raise ShellLinkOracleError(f"LnkParse3 rejected Shell Link: {exc}") from exc
    if observed_warnings:
        messages = "; ".join(str(item.message) for item in observed_warnings[:3])
        raise ShellLinkOracleError(f"LnkParse3 warned while parsing Shell Link: {messages}")
    return view


def require_shell_link_consensus(reads: Mapping[str, object]) -> ShellLinkOracleView:
    """Require exact equality between the two named external-parser observations."""
    if not isinstance(reads, Mapping):
        raise ShellLinkOracleError("Shell Link consensus input must be a parser mapping")
    liblnk = reads.get("liblnk")
    lnkparse3 = reads.get("LnkParse3")
    if type(liblnk) is not ShellLinkOracleView or type(lnkparse3) is not ShellLinkOracleView:
        raise ShellLinkOracleError(
            "typed liblnk and LnkParse3 Shell Link observations are both required"
        )
    if liblnk != lnkparse3:
        raise ShellLinkOracleError(
            "liblnk and LnkParse3 disagree on the type-exact Shell Link semantics"
        )
    return liblnk


def _validate_target_path(path: str) -> None:
    path = _text(path, where="Shell Link target path")
    if (
        not 4 <= len(path) <= 259
        or unicodedata.normalize("NFC", path) != path
        or not ("A" <= path[0] <= "Z" and path[1:3] == ":\\")
        or "\\\\" in path
        or path.endswith("\\")
    ):
        raise ShellLinkOracleError("Shell Link target is outside the canonical local-path profile")
    try:
        encoded = path.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ShellLinkOracleError("Shell Link target path is not portable ASCII") from exc
    if any(byte < 0x20 or byte == 0x7F for byte in encoded):
        raise ShellLinkOracleError("Shell Link target path contains a control character")
    for component in path[3:].split("\\"):
        if (
            not component
            or component in {".", ".."}
            or len(component) > 255
            or component[-1] in {" ", "."}
            or any(character in _INVALID_PATH_CHARACTERS for character in component)
            or _RESERVED_COMPONENT.fullmatch(component)
        ):
            raise ShellLinkOracleError(
                "Shell Link target contains a non-canonical Windows component"
            )


def _validate_description(description: str) -> None:
    description = _text(description, where="Shell Link description")
    if not description.endswith(_MARKED_NAME_SUFFIX):
        raise ShellLinkOracleError("Shell Link description lacks the exact synthetic marker")
    display_name = description[: -len(_MARKED_NAME_SUFFIX)]
    if (
        not 1 <= len(display_name) <= 260 - len(_MARKED_NAME_SUFFIX)
        or unicodedata.normalize("NFC", display_name) != display_name
        or display_name != display_name.strip()
        or MARKER in display_name
        or "\\" in display_name
    ):
        raise ShellLinkOracleError("Shell Link display name is outside the closed profile")
    try:
        encoded = display_name.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ShellLinkOracleError("Shell Link display name is not portable ASCII") from exc
    if any(byte < 0x20 or byte == 0x7F for byte in encoded):
        raise ShellLinkOracleError("Shell Link display name contains a control character")


def _validate_volume_label(label: str) -> None:
    label = _text(label, where="Shell Link volume label")
    if (
        not 1 <= len(label) <= 32
        or unicodedata.normalize("NFC", label) != label
        or label != label.strip()
        or label[-1] == "."
        or any(character in _INVALID_LABEL_CHARACTERS for character in label)
    ):
        raise ShellLinkOracleError("Shell Link volume label is outside the closed profile")
    try:
        encoded = label.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ShellLinkOracleError("Shell Link volume label is not portable ASCII") from exc
    if any(byte < 0x20 or byte == 0x7F for byte in encoded):
        raise ShellLinkOracleError("Shell Link volume label contains a control character")


def validate_artifactforge_shell_link_profile(view: ShellLinkOracleView) -> str:
    """Bind external-parser consensus to ArtifactForge's inert local-file profile."""
    if type(view) is not ShellLinkOracleView:
        raise ShellLinkOracleError("Shell Link profile requires a typed consensus view")
    _validate_target_path(view.target_path)
    _validate_description(view.description)
    _validate_volume_label(view.volume_label)
    for value, bits, where in (
        (view.target_size, 32, "target size"),
        (view.creation_filetime, 64, "creation FILETIME"),
        (view.access_filetime, 64, "access FILETIME"),
        (view.write_filetime, 64, "write FILETIME"),
        (view.volume_serial, 32, "volume serial"),
        (view.drive_type, 32, "drive type"),
        (view.link_flags, 32, "link flags"),
        (view.file_attribute_flags, 32, "file-attribute flags"),
        (view.show_window_value, 32, "show-window value"),
        (view.hot_key_value, 16, "hot-key value"),
        (view.data_block_count, 32, "ExtraData block count"),
    ):
        _integer(value, bits=bits, where=f"Shell Link {where}")
    for value, where in (
        (view.creation_filetime, "creation FILETIME"),
        (view.access_filetime, "access FILETIME"),
        (view.write_filetime, "write FILETIME"),
    ):
        if value % 10 or (
            value != 0
            and not _MIN_PORTABLE_FILETIME <= value <= _MAX_PORTABLE_FILETIME
        ):
            raise ShellLinkOracleError(
                f"Shell Link {where} is outside the zero/unset or portable "
                "whole-microsecond 1970..2242 profile"
            )
    _signed_integer(view.icon_index, bits=32, where="Shell Link icon index")
    if view.link_flags != 0x86:
        raise ShellLinkOracleError("Shell Link flags are not exactly LinkInfo, Name, and Unicode")
    if view.file_attribute_flags != 0x20:
        raise ShellLinkOracleError("Shell Link target attributes are not exactly archive-file")
    if view.drive_type != 3:
        raise ShellLinkOracleError("Shell Link volume is not a fixed drive")
    if (
        view.icon_index != 0
        or view.show_window_value != 1
        or view.hot_key_value != 0
    ):
        raise ShellLinkOracleError("Shell Link launch-display controls are outside the profile")
    if type(view.optional_surfaces) is not tuple or view.optional_surfaces:
        raise ShellLinkOracleError("Shell Link contains an optional execution or ExtraData surface")
    if view.data_block_count != 0:
        raise ShellLinkOracleError("Shell Link contains an optional execution or ExtraData surface")
    return f"profile=local-file-v1,{view.detail()},description=marked"


__all__ = [
    "MAX_SHELL_LINK_ORACLE_BYTES",
    "ShellLinkOracleError",
    "ShellLinkOracleView",
    "liblnk_shell_link_view",
    "lnkparse3_shell_link_view",
    "require_shell_link_consensus",
    "validate_artifactforge_shell_link_profile",
]
