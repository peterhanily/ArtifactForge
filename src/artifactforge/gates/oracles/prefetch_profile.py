# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Independent readers for the bounded Windows-10 Prefetch profile.

The external libraries used by the validity gate both accept MAM-wrapped Prefetch files, but
their shared decompression behavior is EOF-driven.  That is useful interoperability evidence,
not an adequate framing oracle: the MAM header already declares the exact output size.  This
module therefore owns a small expected-size XPRESS-Huffman decoder and a byte-exact parser for
the one Windows-10 v30 variant emitted by ArtifactForge.  ``pyscca`` and ``dissect.target`` are
then used, lazily, as independent semantic consumers.

The closed compression profile is deliberately smaller than general XPRESS-Huffman.  It is a
single sub-64-KiB chunk, uses canonical complete code tables and match lengths 3..17, and ends
with ArtifactForge's post-output sentinel plus the zero word needed by the two EOF-driven
consumers.  Extended lengths, multiple chunks, version 31, alternate v30 layouts, and trailing
data are rejected.  Symbol 256 is a normal match symbol in MS-XCA, not a standardized EOF.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import io
import struct

from artifactforge.disclosure import MARKER


MAM_XPRESS_HUFFMAN_MAGIC = b"MAM\x04"
MAX_PREFETCH_V30_INNER_BYTES = 4096
MAX_PREFETCH_V30_MAM_BYTES = 8192

_MIN_INNER_BYTES = 344 + 4 + 96 + 4
_HUFFMAN_TABLE_BYTES = 256
_MIN_BITSTREAM_BYTES = 4
_HEADER_BYTES = 84
_VARIANT1_FILE_INFORMATION_BYTES = 220
_METRICS_OFFSET = _HEADER_BYTES + _VARIANT1_FILE_INFORMATION_BYTES
_METRICS_BYTES = 32
_TRACE_OFFSET = _METRICS_OFFSET + _METRICS_BYTES
_TRACE_BYTES = 8
_STRINGS_OFFSET = _TRACE_OFFSET + _TRACE_BYTES
_VOLUME_HEADER_BYTES = 96
_DEVICE_PATH = r"\DEVICE\HARDDISKVOLUME1"
_MARKER_SUFFIX = f"\\{MARKER}-SYNTHETIC-NOT-EVIDENCE"
_MIN_PORTABLE_FILETIME = 116_444_736_000_000_000
_MAX_PORTABLE_FILETIME = 202_344_081_920_000_000
_MAX_ORIGINAL_DEVICE_PATH_CHARACTERS = 260
_INVALID_WINDOWS_COMPONENT_CHARACTERS = frozenset('<>:"/|?*')
_RESERVED_WINDOWS_COMPONENTS = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


class PrefetchV30ProfileError(ValueError):
    """A compressed stream, parser observation, or profile value is invalid."""


@dataclass(frozen=True)
class PrefetchV30OracleView:
    """The type-normalized semantic intersection exposed by both external parsers."""

    version: int
    executable_name: str
    prefetch_hash: int
    run_count: int
    last_run_filetimes: tuple[int, ...]
    metric_filenames: tuple[str, ...]

    def detail(self) -> str:
        return (
            f"version={self.version},exe={self.executable_name},"
            f"hash={self.prefetch_hash:08x},runs={self.run_count},"
            f"metrics={len(self.metric_filenames)}"
        )


@dataclass(frozen=True)
class PrefetchV30ProfileView:
    """Byte-exact observation of the supported v30 variant-1 inner record."""

    version: int
    executable_name: str
    prefetch_hash: int
    declared_file_size: int
    run_count: int
    last_run_filetimes: tuple[int, ...]
    metric_filenames: tuple[str, ...]
    filename_strings: tuple[str, ...]
    volume_device_path: str
    volume_creation_filetime: int
    volume_serial_number: int

    def oracle_view(self) -> PrefetchV30OracleView:
        """Project the strict byte view onto the external-parser intersection."""
        return PrefetchV30OracleView(
            version=self.version,
            executable_name=self.executable_name,
            prefetch_hash=self.prefetch_hash,
            run_count=self.run_count,
            last_run_filetimes=self.last_run_filetimes,
            metric_filenames=self.metric_filenames,
        )

    def detail(self) -> str:
        return (
            f"version={self.version},exe={self.executable_name},"
            f"hash={self.prefetch_hash:08x},runs={self.run_count},"
            f"volume={self.volume_device_path}/{self.volume_serial_number:08x}"
        )


def _integer(value: object, *, bits: int, where: str) -> int:
    if type(value) is bool or not isinstance(value, int):
        raise PrefetchV30ProfileError(f"{where} is not an unsigned {bits}-bit integer")
    converted = int(value)  # cstruct's uint subclasses are intentionally normalized here.
    if not 0 <= converted < 1 << bits:
        raise PrefetchV30ProfileError(f"{where} is not an unsigned {bits}-bit integer")
    return converted


def _text(value: object, *, where: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise PrefetchV30ProfileError(f"{where} is not non-empty NUL-free text")
    return value


def _ascii_path(value: object, *, where: str) -> str:
    value = _text(value, where=where)
    if not value.startswith("\\") or value.endswith("\\") or "\\\\" in value:
        raise PrefetchV30ProfileError(f"{where} is not a canonical absolute path")
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise PrefetchV30ProfileError(f"{where} is not portable ASCII") from exc
    if any(byte < 0x20 or byte == 0x7F for byte in encoded):
        raise PrefetchV30ProfileError(f"{where} contains a control character")
    return value


def _mam_input(data: object) -> tuple[bytes, int]:
    if type(data) is not bytes:
        raise PrefetchV30ProfileError("MAM Prefetch input must be immutable bytes")
    minimum = 8 + _HUFFMAN_TABLE_BYTES + _MIN_BITSTREAM_BYTES
    if not minimum <= len(data) <= MAX_PREFETCH_V30_MAM_BYTES:
        raise PrefetchV30ProfileError(
            f"MAM Prefetch input must contain {minimum}..{MAX_PREFETCH_V30_MAM_BYTES} bytes"
        )
    if data[:4] != MAM_XPRESS_HUFFMAN_MAGIC:
        raise PrefetchV30ProfileError("Prefetch wrapper is not MAM algorithm 4")
    expected_size = struct.unpack_from("<I", data, 4)[0]
    if not _MIN_INNER_BYTES <= expected_size <= MAX_PREFETCH_V30_INNER_BYTES:
        raise PrefetchV30ProfileError("MAM declared output size is outside the v30 profile")
    return data, expected_size


class _WordBitReader:
    """Read MSB-first bits from little-endian 16-bit XPRESS words."""

    __slots__ = ("_data", "position")

    def __init__(self, data: bytes):
        if len(data) < _MIN_BITSTREAM_BYTES or len(data) % 2:
            raise PrefetchV30ProfileError(
                "XPRESS-Huffman bitstream must contain an even number of at least four bytes"
            )
        self._data = data
        self.position = 0

    @property
    def bit_count(self) -> int:
        return len(self._data) * 8

    def read(self, count: int, *, where: str) -> int:
        if count < 0 or self.position + count > self.bit_count:
            raise PrefetchV30ProfileError(f"truncated XPRESS-Huffman {where}")
        result = 0
        for _ in range(count):
            word_offset = (self.position // 16) * 2
            word = self._data[word_offset] | self._data[word_offset + 1] << 8
            bit = (word >> (15 - self.position % 16)) & 1
            result = (result << 1) | bit
            self.position += 1
        return result

    def tail_is_zero(self) -> bool:
        position = self.position
        try:
            while self.position < self.bit_count:
                if self.read(1, where="post-output padding"):
                    return False
            return True
        finally:
            self.position = position


def _canonical_decoder(table: bytes) -> dict[tuple[int, int], int]:
    if len(table) != _HUFFMAN_TABLE_BYTES:
        raise PrefetchV30ProfileError("truncated XPRESS-Huffman code-length table")
    lengths: list[int] = []
    for value in table:
        lengths.extend((value & 0x0F, value >> 4))
    if not any(lengths) or lengths[256] == 0:
        raise PrefetchV30ProfileError(
            "XPRESS-Huffman table lacks symbols or ArtifactForge's post-output sentinel"
        )
    if sum(1 << (15 - length) for length in lengths if length) != 1 << 15:
        raise PrefetchV30ProfileError("XPRESS-Huffman code-length table is not complete")

    decoder: dict[tuple[int, int], int] = {}
    code = 0
    previous_length = 0
    for length, symbol in sorted(
        (length, symbol) for symbol, length in enumerate(lengths) if length
    ):
        code <<= length - previous_length
        if code >= 1 << length:
            raise PrefetchV30ProfileError("XPRESS-Huffman code-length table is over-subscribed")
        decoder[length, code] = symbol
        code += 1
        previous_length = length
    return decoder


def _decode_symbol(reader: _WordBitReader, decoder: Mapping[tuple[int, int], int]) -> int:
    code = 0
    for length in range(1, 16):
        code = code << 1 | reader.read(1, where="symbol")
        symbol = decoder.get((length, code))
        if symbol is not None:
            return symbol
    raise PrefetchV30ProfileError("XPRESS-Huffman bits do not resolve to a table symbol")


def _decode_expected_size_xpress_huffman(payload: bytes, expected_size: int) -> bytes:
    if len(payload) < _HUFFMAN_TABLE_BYTES + _MIN_BITSTREAM_BYTES:
        raise PrefetchV30ProfileError("truncated XPRESS-Huffman payload")
    if len(payload) >= expected_size:
        raise PrefetchV30ProfileError(
            "XPRESS-Huffman payload is not smaller than its declared output"
        )
    decoder = _canonical_decoder(payload[:_HUFFMAN_TABLE_BYTES])
    reader = _WordBitReader(payload[_HUFFMAN_TABLE_BYTES:])
    output = bytearray()
    token_count = 0

    while len(output) < expected_size:
        token_count += 1
        if token_count > expected_size:
            raise PrefetchV30ProfileError("XPRESS-Huffman token count exceeds the output bound")
        symbol = _decode_symbol(reader, decoder)
        if symbol < 256:
            output.append(symbol)
            continue

        match_symbol = symbol - 256
        length_code = match_symbol & 0x0F
        offset_bits = match_symbol >> 4
        if length_code == 15:
            raise PrefetchV30ProfileError(
                "XPRESS-Huffman extended match lengths are outside the closed profile"
            )
        distance = (1 << offset_bits) + reader.read(offset_bits, where="match-distance suffix")
        match_length = length_code + 3
        if distance > len(output):
            raise PrefetchV30ProfileError("XPRESS-Huffman match points before decoded output")
        if len(output) + match_length > expected_size:
            raise PrefetchV30ProfileError("XPRESS-Huffman token overshoots declared output size")
        for _ in range(match_length):
            output.append(output[-distance])

    # The EOF-driven consumers prefetch 16-bit words.  ArtifactForge's deterministic stream
    # therefore carries symbol 256 after the declared output, pads that word with zero bits,
    # then adds one full zero word.  Symbol 256 is an ordinary len=3/distance=1 match in MS-XCA;
    # only its position outside the MAM-declared output makes it our deterministic sentinel.
    if _decode_symbol(reader, decoder) != 256:
        raise PrefetchV30ProfileError("XPRESS-Huffman post-output sentinel is not symbol 256")
    padded_guard_end = ((reader.position + 15) // 16) * 16
    if reader.bit_count != padded_guard_end + 16:
        raise PrefetchV30ProfileError(
            "XPRESS-Huffman stream does not end with exactly one post-output zero word"
        )
    if not reader.tail_is_zero():
        raise PrefetchV30ProfileError("XPRESS-Huffman post-output padding is non-zero")
    return bytes(output)


def decode_mam_xpress_huffman(data: bytes) -> bytes:
    """Decode one bounded, canonical expected-size MAM XPRESS-Huffman stream."""
    data, expected_size = _mam_input(data)
    return _decode_expected_size_xpress_huffman(data[8:], expected_size)


def _fixed_utf16_name(data: bytes, *, where: str) -> str:
    if len(data) % 2:
        raise PrefetchV30ProfileError(f"{where} has an odd UTF-16LE byte count")
    try:
        decoded = data.decode("utf-16-le", errors="strict")
    except UnicodeDecodeError as exc:
        raise PrefetchV30ProfileError(f"{where} is not UTF-16LE") from exc
    terminator = decoded.find("\x00")
    if terminator <= 0 or any(character != "\x00" for character in decoded[terminator:]):
        raise PrefetchV30ProfileError(f"{where} is not canonically NUL padded")
    name = decoded[:terminator]
    try:
        name.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise PrefetchV30ProfileError(f"{where} is not portable ASCII") from exc
    return name


def _utf16z_strings(data: bytes, *, where: str) -> tuple[str, ...]:
    if len(data) % 2:
        raise PrefetchV30ProfileError(f"{where} has an odd UTF-16LE byte count")
    try:
        decoded = data.decode("utf-16-le", errors="strict")
    except UnicodeDecodeError as exc:
        raise PrefetchV30ProfileError(f"{where} is not UTF-16LE") from exc
    if not decoded.endswith("\x00"):
        raise PrefetchV30ProfileError(f"{where} lacks its final end-of-string character")
    strings = tuple(decoded[:-1].split("\x00"))
    if any(not value for value in strings):
        raise PrefetchV30ProfileError(f"{where} contains an empty string")
    return strings


def _u32(data: bytes, offset: int) -> int:
    try:
        return struct.unpack_from("<I", data, offset)[0]
    except struct.error as exc:
        raise PrefetchV30ProfileError("truncated v30 Prefetch integer") from exc


def _u64(data: bytes, offset: int) -> int:
    try:
        return struct.unpack_from("<Q", data, offset)[0]
    except struct.error as exc:
        raise PrefetchV30ProfileError("truncated v30 Prefetch integer") from exc


def parse_prefetch_v30_variant1(data: bytes) -> PrefetchV30ProfileView:
    """Parse the exact uncompressed Windows-10 v30 variant-1 wire layout."""
    if type(data) is not bytes:
        raise PrefetchV30ProfileError("v30 Prefetch inner input must be immutable bytes")
    if not _MIN_INNER_BYTES <= len(data) <= MAX_PREFETCH_V30_INNER_BYTES:
        raise PrefetchV30ProfileError("v30 Prefetch inner size is outside the closed profile")
    if _u32(data, 0) != 30:
        raise PrefetchV30ProfileError("Prefetch version is not exactly 30")
    if data[4:8] != b"SCCA" or _u32(data, 8) != 0:
        raise PrefetchV30ProfileError("Prefetch signature or reserved header field is invalid")
    if _u32(data, 12) != len(data):
        raise PrefetchV30ProfileError("Prefetch header size does not equal decoded bytes")
    executable_name = _fixed_utf16_name(data[16:76], where="Prefetch executable name")
    prefetch_hash = _u32(data, 76)
    if _u32(data, 80) != 0:
        raise PrefetchV30ProfileError("Prefetch header flag is outside variant 1")

    fields = struct.unpack_from("<9I", data, _HEADER_BYTES)
    (
        metrics_offset,
        metrics_count,
        trace_offset,
        trace_count,
        strings_offset,
        strings_size,
        volumes_offset,
        volume_count,
        volumes_size,
    ) = fields
    if (metrics_offset, metrics_count) != (_METRICS_OFFSET, 1):
        raise PrefetchV30ProfileError("Prefetch metrics extent is outside variant 1")
    if (trace_offset, trace_count) != (_TRACE_OFFSET, 1):
        raise PrefetchV30ProfileError("Prefetch trace-chain extent is outside variant 1")
    if strings_offset != _STRINGS_OFFSET or strings_size % 2:
        raise PrefetchV30ProfileError("Prefetch filename-strings extent is outside variant 1")
    if volumes_offset != strings_offset + strings_size or volume_count != 1:
        raise PrefetchV30ProfileError("Prefetch volume extent is outside variant 1")
    if volumes_size != len(data) - volumes_offset:
        raise PrefetchV30ProfileError("Prefetch volume size does not consume the inner record")
    if any(data[120:128]) or any(data[192:208]) or any(data[212:_METRICS_OFFSET]):
        raise PrefetchV30ProfileError("Prefetch file-information reserved bytes are non-zero")

    last_run_filetimes = tuple(_u64(data, 128 + index * 8) for index in range(8))
    run_count = _u32(data, 208)
    metric_values = struct.unpack_from("<6IQ", data, metrics_offset)
    if metric_values[:4] != (0, 1, 1, 0) or metric_values[5:] != (0x200, 0):
        raise PrefetchV30ProfileError("Prefetch file-metrics entry is outside variant 1")
    if data[trace_offset:strings_offset] != b"\x01\x00\x00\x00\x02\x01\x01\x01":
        raise PrefetchV30ProfileError("Prefetch trace-chain entry is outside variant 1")

    filename_strings = _utf16z_strings(
        data[strings_offset:volumes_offset], where="Prefetch filename strings"
    )
    if len(filename_strings) != 2:
        raise PrefetchV30ProfileError(
            "Prefetch filename block does not contain exactly two strings"
        )
    target_path = _ascii_path(filename_strings[0], where="Prefetch metric filename")
    _ascii_path(filename_strings[1], where="Prefetch marker filename")
    if metric_values[4] != len(target_path):
        raise PrefetchV30ProfileError("Prefetch metric filename length is inconsistent")

    if volumes_size < _VOLUME_HEADER_BYTES + 4:
        raise PrefetchV30ProfileError("Prefetch volume block is truncated")
    device_offset = _u32(data, volumes_offset)
    device_characters = _u32(data, volumes_offset + 4)
    volume_creation_filetime = _u64(data, volumes_offset + 8)
    volume_serial_number = _u32(data, volumes_offset + 16)
    if device_offset != _VOLUME_HEADER_BYTES or any(
        data[volumes_offset + 20 : volumes_offset + _VOLUME_HEADER_BYTES]
    ):
        raise PrefetchV30ProfileError("Prefetch v30 volume header is outside variant 1")
    device_bytes = data[volumes_offset + device_offset :]
    if len(device_bytes) != (device_characters + 1) * 2:
        raise PrefetchV30ProfileError("Prefetch volume device-path extent is inconsistent")
    device_strings = _utf16z_strings(device_bytes, where="Prefetch volume device path")
    if len(device_strings) != 1:
        raise PrefetchV30ProfileError("Prefetch volume contains more than one device path")
    volume_device_path = _ascii_path(device_strings[0], where="Prefetch volume device path")

    return PrefetchV30ProfileView(
        version=30,
        executable_name=executable_name,
        prefetch_hash=prefetch_hash,
        declared_file_size=len(data),
        run_count=run_count,
        last_run_filetimes=last_run_filetimes,
        metric_filenames=(target_path,),
        filename_strings=filename_strings,
        volume_device_path=volume_device_path,
        volume_creation_filetime=volume_creation_filetime,
        volume_serial_number=volume_serial_number,
    )


def parse_mam_prefetch_v30_variant1(data: bytes) -> PrefetchV30ProfileView:
    """Decode the MAM wrapper and parse its exact v30 variant-1 inner record."""
    return parse_prefetch_v30_variant1(decode_mam_xpress_huffman(data))


def _external_name(value: object, *, where: str) -> str:
    if not isinstance(value, bytes):
        raise PrefetchV30ProfileError(f"{where} is not a fixed byte field")
    return _fixed_utf16_name(bytes(value), where=where)


def _checked_oracle_view(view: PrefetchV30OracleView, *, where: str) -> PrefetchV30OracleView:
    if view.version != 30:
        raise PrefetchV30ProfileError(f"{where} observed a Prefetch version other than 30")
    if len(view.last_run_filetimes) != 8 or len(view.metric_filenames) != 1:
        raise PrefetchV30ProfileError(f"{where} observations are outside the bounded profile")
    return view


def pyscca_prefetch_v30_view(data: bytes) -> PrefetchV30OracleView:
    """Read one bounded MAM Prefetch through libyal's ``pyscca`` binding."""
    data, _ = _mam_input(data)
    import pyscca

    parsed = pyscca.file()
    try:
        parsed.open_file_object(io.BytesIO(data))
        metric_count = _integer(
            parsed.get_number_of_file_metrics_entries(),
            bits=32,
            where="pyscca metric count",
        )
        filename_count = _integer(
            parsed.get_number_of_filenames(), bits=32, where="pyscca filename count"
        )
        volume_count = _integer(
            parsed.get_number_of_volumes(), bits=32, where="pyscca volume count"
        )
        if (metric_count, filename_count, volume_count) != (1, 2, 1):
            raise PrefetchV30ProfileError("pyscca observations are outside the bounded profile")
        metric_filenames = tuple(
            _ascii_path(
                parsed.get_file_metrics_entry(index).get_filename(),
                where=f"pyscca metric filename {index}",
            )
            for index in range(metric_count)
        )
        if parsed.get_filename(0) != metric_filenames[0]:
            raise PrefetchV30ProfileError("pyscca filename and metric observations disagree")
        return _checked_oracle_view(
            PrefetchV30OracleView(
                version=_integer(
                    parsed.get_format_version(), bits=32, where="pyscca format version"
                ),
                executable_name=_text(
                    parsed.get_executable_filename(), where="pyscca executable name"
                ),
                prefetch_hash=_integer(
                    parsed.get_prefetch_hash(), bits=32, where="pyscca Prefetch hash"
                ),
                run_count=_integer(parsed.get_run_count(), bits=32, where="pyscca run count"),
                last_run_filetimes=tuple(
                    _integer(
                        parsed.get_last_run_time_as_integer(index),
                        bits=64,
                        where=f"pyscca last-run FILETIME {index}",
                    )
                    for index in range(8)
                ),
                metric_filenames=metric_filenames,
            ),
            where="pyscca",
        )
    except PrefetchV30ProfileError:
        raise
    except Exception as exc:
        raise PrefetchV30ProfileError(f"pyscca rejected v30 Prefetch: {exc}") from exc
    finally:
        try:
            parsed.close()
        except OSError:
            pass


def dissect_prefetch_v30_view(data: bytes) -> PrefetchV30OracleView:
    """Read one bounded MAM Prefetch through ``dissect.target``'s Prefetch parser."""
    data, _ = _mam_input(data)
    from dissect.target.plugins.os.windows.prefetch import Prefetch

    try:
        parsed = Prefetch(io.BytesIO(data))
        # Dissect's raw decoder is EOF-driven and can expose the ordinary symbol-256
        # post-output sentinel as three extra bytes.  This adapter therefore observes only
        # decoded Prefetch semantics; wrapper framing is owned by our expected-size reader.
        if bytes(parsed.header.signature) != b"SCCA":
            raise PrefetchV30ProfileError("Dissect did not observe the SCCA signature")
        metrics = parsed.metrics
        if type(metrics) is not list or len(metrics) != 1:
            raise PrefetchV30ProfileError("Dissect metric observations are outside the profile")
        return _checked_oracle_view(
            PrefetchV30OracleView(
                version=_integer(parsed.version, bits=32, where="Dissect format version"),
                executable_name=_external_name(parsed.header.name, where="Dissect executable name"),
                prefetch_hash=_integer(parsed.header.hash, bits=32, where="Dissect Prefetch hash"),
                run_count=_integer(parsed.fn.run_count, bits=32, where="Dissect run count"),
                last_run_filetimes=(
                    _integer(
                        parsed.fn.last_run_time,
                        bits=64,
                        where="Dissect last-run FILETIME 0",
                    ),
                    *tuple(
                        _integer(value, bits=64, where=f"Dissect last-run FILETIME {index}")
                        for index, value in enumerate(parsed.fn.last_run_remains, start=1)
                    ),
                ),
                metric_filenames=tuple(
                    _ascii_path(value, where=f"Dissect metric filename {index}")
                    for index, value in enumerate(metrics)
                ),
            ),
            where="Dissect",
        )
    except PrefetchV30ProfileError:
        raise
    except Exception as exc:
        raise PrefetchV30ProfileError(f"Dissect rejected v30 Prefetch: {exc}") from exc


def require_prefetch_v30_consensus(
    reads: Mapping[str, object],
) -> PrefetchV30OracleView:
    """Require exact typed equality between the named external-parser observations."""
    if not isinstance(reads, Mapping):
        raise PrefetchV30ProfileError("Prefetch consensus input must be a parser mapping")
    pyscca_view = reads.get("pyscca")
    dissect_view = reads.get("dissect.target-prefetch")
    if (
        type(pyscca_view) is not PrefetchV30OracleView
        or type(dissect_view) is not PrefetchV30OracleView
    ):
        raise PrefetchV30ProfileError(
            "typed pyscca and dissect.target-prefetch observations are both required"
        )
    if pyscca_view != dissect_view:
        raise PrefetchV30ProfileError(
            "pyscca and dissect.target-prefetch disagree on type-exact Prefetch semantics"
        )
    return pyscca_view


def prefetch_vista_path_hash(full_path: str) -> int:
    """Return the Vista-and-later Prefetch path hash used by the v30 profile."""
    full_path = _ascii_path(full_path, where="Prefetch hash input path")
    result = 314159
    for byte in full_path.upper().encode("utf-16-le"):
        result = (result * 37 + byte) & 0xFFFFFFFF
    return result


def _portable_filetime(value: object, *, where: str, allow_zero: bool = False) -> int:
    value = _integer(value, bits=64, where=where)
    if value == 0 and allow_zero:
        return value
    if value % 10 or not _MIN_PORTABLE_FILETIME <= value <= _MAX_PORTABLE_FILETIME:
        raise PrefetchV30ProfileError(
            f"{where} is outside the portable whole-microsecond 1970..2242 profile"
        )
    return value


def validate_artifactforge_prefetch_v30_profile(
    view: PrefetchV30ProfileView,
    consensus: PrefetchV30OracleView,
) -> str:
    """Bind strict bytes and dual-parser consensus to ArtifactForge's one-volume profile."""
    if type(view) is not PrefetchV30ProfileView:
        raise PrefetchV30ProfileError("Prefetch profile requires a typed strict-reader view")
    if type(consensus) is not PrefetchV30OracleView:
        raise PrefetchV30ProfileError("Prefetch profile requires a typed parser consensus")
    if view.oracle_view() != consensus:
        raise PrefetchV30ProfileError("strict and external Prefetch observations disagree")
    version = _integer(view.version, bits=32, where="Prefetch version")
    declared_size = _integer(view.declared_file_size, bits=32, where="Prefetch declared file size")
    _integer(view.prefetch_hash, bits=32, where="Prefetch hash")
    if version != 30 or not _MIN_INNER_BYTES <= declared_size <= MAX_PREFETCH_V30_INNER_BYTES:
        raise PrefetchV30ProfileError("Prefetch strict view is outside v30 variant 1")
    if type(view.last_run_filetimes) is not tuple or len(view.last_run_filetimes) != 8:
        raise PrefetchV30ProfileError("Prefetch strict view lacks eight last-run FILETIMEs")
    last_run_filetimes = tuple(
        _integer(value, bits=64, where=f"Prefetch last-run FILETIME {index}")
        for index, value in enumerate(view.last_run_filetimes)
    )
    if any(last_run_filetimes[1:]):
        raise PrefetchV30ProfileError("Prefetch previous-run FILETIMEs are outside the profile")
    last_run_filetime = _portable_filetime(
        last_run_filetimes[0], where="Prefetch last-run FILETIME"
    )
    volume_creation_filetime = _portable_filetime(
        view.volume_creation_filetime, where="Prefetch volume-creation FILETIME"
    )
    run_count = _integer(view.run_count, bits=32, where="Prefetch run count")
    serial = _integer(view.volume_serial_number, bits=32, where="Prefetch volume serial")
    if run_count == 0 or serial == 0:
        raise PrefetchV30ProfileError("Prefetch run count and volume serial must be non-zero")

    volume_token = f"\\VOLUME{{{volume_creation_filetime:016x}-{serial:08x}}}"
    if view.volume_device_path != volume_token:
        raise PrefetchV30ProfileError(
            "Prefetch sole volume does not use its creation-time/serial token"
        )
    if type(view.metric_filenames) is not tuple or len(view.metric_filenames) != 1:
        raise PrefetchV30ProfileError("Prefetch profile requires exactly one metric filename")
    recorded_path = _ascii_path(view.metric_filenames[0], where="Prefetch recorded executable path")
    prefix = volume_token + "\\"
    if not recorded_path.startswith(prefix):
        raise PrefetchV30ProfileError("Prefetch executable is not accounted for by its sole volume")
    tail = recorded_path[len(volume_token) :]
    if (
        tail != tail.upper()
        or "/" in tail
        or any(component in {".", ".."} for component in tail.split("\\"))
    ):
        raise PrefetchV30ProfileError("Prefetch executable-path tail is not canonical uppercase")
    expected_marker = volume_token + _MARKER_SUFFIX
    if type(view.filename_strings) is not tuple or view.filename_strings != (
        recorded_path,
        expected_marker,
    ):
        raise PrefetchV30ProfileError(
            "Prefetch filename strings do not share the sole canonical volume token"
        )
    executable_name = _text(view.executable_name, where="Prefetch executable name")
    if (
        len(executable_name) > 29
        or executable_name != executable_name.upper()
        or recorded_path.rsplit("\\", 1)[-1] != executable_name
    ):
        raise PrefetchV30ProfileError("Prefetch executable name and recorded path disagree")
    original_device_path = _DEVICE_PATH + tail
    if len(original_device_path) > _MAX_ORIGINAL_DEVICE_PATH_CHARACTERS:
        raise PrefetchV30ProfileError("Prefetch original device path exceeds the profile bound")
    for component in tail[1:].split("\\"):
        stem = component.split(".", 1)[0].upper()
        if (
            not component
            or len(component) > 255
            or component[-1] in {" ", "."}
            or any(character in _INVALID_WINDOWS_COMPONENT_CHARACTERS for character in component)
            or stem in _RESERVED_WINDOWS_COMPONENTS
        ):
            raise PrefetchV30ProfileError(
                "Prefetch executable path contains a non-canonical Windows component"
            )
    if view.prefetch_hash != prefetch_vista_path_hash(original_device_path):
        raise PrefetchV30ProfileError("Prefetch hash does not bind the original device path")
    if volume_creation_filetime >= last_run_filetime:
        raise PrefetchV30ProfileError(
            "Prefetch volume creation must precede the recorded execution"
        )
    return f"profile=windows10-v30-variant1,{view.detail()},marker=volume-bound"


__all__ = [
    "MAM_XPRESS_HUFFMAN_MAGIC",
    "MAX_PREFETCH_V30_INNER_BYTES",
    "MAX_PREFETCH_V30_MAM_BYTES",
    "PrefetchV30OracleView",
    "PrefetchV30ProfileError",
    "PrefetchV30ProfileView",
    "decode_mam_xpress_huffman",
    "dissect_prefetch_v30_view",
    "parse_mam_prefetch_v30_variant1",
    "parse_prefetch_v30_variant1",
    "prefetch_vista_path_hash",
    "pyscca_prefetch_v30_view",
    "require_prefetch_v30_consensus",
    "validate_artifactforge_prefetch_v30_profile",
]
