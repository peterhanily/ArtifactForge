# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Deterministic, bounded XPRESS-Huffman compression for one small chunk.

This module intentionally implements only the profile ArtifactForge needs: one
non-empty chunk smaller than 64 KiB, ordinary three-to-seventeen-byte matches,
and deterministic post-output padding. It does not emit the outer ``MAM``
container used by Windows Prefetch files.

XPRESS-Huffman has no end-of-stream symbol. MAM supplies the exact expected
uncompressed size. Symbol 256 is an ordinary length-three, distance-one match;
ArtifactForge emits one after the declared output only as a profile-specific
sentinel that its expected-size reader can validate. An EOF-driven decoder can
therefore expose padding bytes and is not an exact-output oracle for this profile.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import heapq
import struct
from typing import Mapping, Sequence

MAX_CHUNK_SIZE = 65_535
MAX_DISTANCE = 65_535
MIN_MATCH = 3
MAX_MATCH = 17
SYMBOL_COUNT = 512
_POST_OUTPUT_SENTINEL_SYMBOL = 256
LENGTH_TABLE_SIZE = SYMBOL_COUNT // 2
MAX_CODE_BITS = 15
_FALLBACK_CODE_BITS = 9
_MAX_CANDIDATES = 256


class XpressHuffmanError(ValueError):
    """The input cannot be represented by this bounded compression profile."""


@dataclass(frozen=True, slots=True)
class _Token:
    literal: int | None = None
    length: int = 0
    distance: int = 0

    @property
    def is_literal(self) -> bool:
        return self.literal is not None


class _WordBitWriter:
    """Write MSB-first bits into little-endian 16-bit storage words."""

    __slots__ = ("_current", "_used", "_words")

    def __init__(self) -> None:
        self._current = 0
        self._used = 0
        self._words = bytearray()

    def write(self, value: int, bit_count: int) -> None:
        if bit_count < 0 or value < 0 or value >= (1 << bit_count):
            raise XpressHuffmanError("bit value does not fit its declared width")

        for shift in range(bit_count - 1, -1, -1):
            self._current = (self._current << 1) | ((value >> shift) & 1)
            self._used += 1
            if self._used == 16:
                self._words.extend(struct.pack("<H", self._current))
                self._current = 0
                self._used = 0

    def finish(self) -> bytes:
        if self._used:
            self._current <<= 16 - self._used
            self._words.extend(struct.pack("<H", self._current))

        # Expected-size readers may refill while validating the profile's
        # post-output sentinel.  A complete zero word is therefore part of the
        # encoded chunk.
        self._words.extend(b"\x00\x00")
        return bytes(self._words)


def compress_xpress_huffman(data: bytes) -> bytes:
    """Return one raw XPRESS-Huffman chunk, refusing expansion.

    The returned bytes begin with the 256-byte packed code-length table.  The
    caller is responsible for any container header and uncompressed-size field.
    Inputs must be immutable ``bytes`` and contain between 1 and 65,535 bytes.
    """

    if type(data) is not bytes:
        raise TypeError("XPRESS-Huffman input must be bytes")
    if not data:
        raise XpressHuffmanError("XPRESS-Huffman input must not be empty")
    if len(data) > MAX_CHUNK_SIZE:
        raise XpressHuffmanError("XPRESS-Huffman input must be smaller than 64 KiB")

    tokens = _tokenize(data)
    frequencies = Counter(_token_symbol(token) for token in tokens)
    frequencies[_POST_OUTPUT_SENTINEL_SYMBOL] += 1
    lengths = _bounded_code_lengths(frequencies)
    codes = _canonical_codes(lengths)

    writer = _WordBitWriter()
    for token in tokens:
        symbol = _token_symbol(token)
        code, width = codes[symbol]
        writer.write(code, width)
        if not token.is_literal:
            distance_bits = token.distance.bit_length() - 1
            writer.write(token.distance - (1 << distance_bits), distance_bits)

    sentinel_code, sentinel_width = codes[_POST_OUTPUT_SENTINEL_SYMBOL]
    writer.write(sentinel_code, sentinel_width)

    encoded = _pack_length_table(lengths) + writer.finish()
    if len(encoded) >= len(data):
        raise XpressHuffmanError("XPRESS-Huffman output is not smaller than the uncompressed input")
    return encoded


def _tokenize(data: bytes) -> tuple[_Token, ...]:
    positions: dict[bytes, list[int]] = defaultdict(list)
    tokens: list[_Token] = []
    offset = 0

    while offset < len(data):
        best_length = 0
        best_distance = 0
        if offset + MIN_MATCH <= len(data):
            key = data[offset : offset + MIN_MATCH]
            candidates = positions.get(key, ())
            limit = min(MAX_MATCH, len(data) - offset)

            for previous in reversed(candidates[-_MAX_CANDIDATES:]):
                distance = offset - previous
                if distance > MAX_DISTANCE:
                    break

                length = MIN_MATCH
                while length < limit:
                    source = previous + length if length < distance else offset + length - distance
                    if data[source] != data[offset + length]:
                        break
                    length += 1

                if length > best_length or (
                    length == best_length and (best_distance == 0 or distance < best_distance)
                ):
                    best_length = length
                    best_distance = distance
                if best_length == limit:
                    break

        if best_length >= MIN_MATCH:
            tokens.append(_Token(length=best_length, distance=best_distance))
            consumed = best_length
        else:
            tokens.append(_Token(literal=data[offset]))
            consumed = 1

        end = offset + consumed
        for position in range(offset, end):
            if position + MIN_MATCH <= len(data):
                positions[data[position : position + MIN_MATCH]].append(position)
        offset = end

    return tuple(tokens)


def _token_symbol(token: _Token) -> int:
    if token.is_literal:
        assert token.literal is not None
        if not 0 <= token.literal <= 255:
            raise XpressHuffmanError("literal is outside the byte range")
        return token.literal

    if not MIN_MATCH <= token.length <= MAX_MATCH:
        raise XpressHuffmanError("match length is outside the bounded profile")
    if not 1 <= token.distance <= MAX_DISTANCE:
        raise XpressHuffmanError("match distance is outside the bounded profile")
    distance_bits = token.distance.bit_length() - 1
    return _POST_OUTPUT_SENTINEL_SYMBOL + (token.length - MIN_MATCH) + (16 * distance_bits)


def _bounded_code_lengths(frequencies: Mapping[int, int]) -> tuple[int, ...]:
    """Build a complete tree no deeper than 15 bits, or use fixed 9-bit codes."""

    fallback = (_FALLBACK_CODE_BITS,) * SYMBOL_COUNT
    used: list[tuple[int, int]] = []
    for symbol, frequency in frequencies.items():
        if not 0 <= symbol < SYMBOL_COUNT or frequency <= 0:
            raise XpressHuffmanError("invalid Huffman frequency table")
        used.append((symbol, frequency))

    if len(used) < 2:
        return fallback

    # Heap order includes the smallest descendant symbol and a serial number,
    # so equal-frequency trees are stable across Python versions and processes.
    heap: list[tuple[int, int, int, int | tuple[object, object]]] = []
    serial = 0
    for symbol, frequency in sorted(used):
        heapq.heappush(heap, (frequency, symbol, serial, symbol))
        serial += 1

    while len(heap) > 1:
        left = heapq.heappop(heap)
        right = heapq.heappop(heap)
        node = (left[3], right[3])
        heapq.heappush(
            heap,
            (left[0] + right[0], min(left[1], right[1]), serial, node),
        )
        serial += 1

    lengths = [0] * SYMBOL_COUNT
    stack: list[tuple[int | tuple[object, object], int]] = [(heap[0][3], 0)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, int):
            lengths[node] = depth
            continue
        left, right = node
        stack.append((right, depth + 1))
        stack.append((left, depth + 1))

    if max(lengths) > MAX_CODE_BITS:
        return fallback

    result = tuple(lengths)
    try:
        _canonical_codes(result)
    except XpressHuffmanError:
        return fallback
    return result


def _canonical_codes(lengths: Sequence[int]) -> tuple[tuple[int, int], ...]:
    if len(lengths) != SYMBOL_COUNT:
        raise XpressHuffmanError("Huffman table must contain 512 code lengths")
    if any(type(length) is not int or not 0 <= length <= MAX_CODE_BITS for length in lengths):
        raise XpressHuffmanError("Huffman code length is outside the format range")

    ordered = sorted((length, symbol) for symbol, length in enumerate(lengths) if length)
    if not ordered:
        raise XpressHuffmanError("Huffman table contains no codes")

    codes = [(0, 0)] * SYMBOL_COUNT
    code = 0
    previous_length = 0
    for length, symbol in ordered:
        code <<= length - previous_length
        if code >= (1 << length):
            raise XpressHuffmanError("Huffman table is oversubscribed")
        codes[symbol] = (code, length)
        code += 1
        previous_length = length

    if code != (1 << previous_length):
        raise XpressHuffmanError("Huffman table is incomplete")
    return tuple(codes)


def _pack_length_table(lengths: Sequence[int]) -> bytes:
    if len(lengths) != SYMBOL_COUNT:
        raise XpressHuffmanError("Huffman table must contain 512 code lengths")
    return bytes(lengths[index] | (lengths[index + 1] << 4) for index in range(0, SYMBOL_COUNT, 2))
