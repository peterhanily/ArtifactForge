# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Conformance tests for the bounded, expected-size XPRESS-Huffman encoder.

The decoder below deliberately shares no encoder helpers.  It reconstructs the
canonical table and interprets storage words directly, which makes round trips
useful against bit-order, table-packing, match, and post-output-padding regressions.
"""

from __future__ import annotations

import hashlib

import pytest

from artifactforge.artifacts.xpress_huffman import (
    MAX_CHUNK_SIZE,
    XpressHuffmanError,
    _Token,
    _bounded_code_lengths,
    _canonical_codes,
    _token_symbol,
    _tokenize,
    compress_xpress_huffman,
)


class _IndependentBitReader:
    def __init__(self, data: bytes) -> None:
        if len(data) % 2:
            raise AssertionError("bitstream is not word aligned")
        self.data = data
        self.bit_position = 0

    @property
    def remaining(self) -> int:
        return (len(self.data) * 8) - self.bit_position

    def read(self, width: int) -> int:
        if width < 0 or self.remaining < width:
            raise AssertionError("truncated bitstream")
        value = 0
        for _ in range(width):
            word_offset = (self.bit_position // 16) * 2
            bit_in_word = self.bit_position % 16
            word = int.from_bytes(self.data[word_offset : word_offset + 2], "little")
            value = (value << 1) | ((word >> (15 - bit_in_word)) & 1)
            self.bit_position += 1
        return value


def _independent_decoder(payload: bytes, expected_size: int) -> bytes:
    if len(payload) < 260:
        raise AssertionError("truncated XPRESS-Huffman payload")

    lengths: list[int] = []
    for packed in payload[:256]:
        lengths.extend((packed & 0x0F, packed >> 4))

    ordered = sorted((width, symbol) for symbol, width in enumerate(lengths) if width)
    if not ordered:
        raise AssertionError("empty Huffman table")

    decoding: dict[tuple[int, int], int] = {}
    code = 0
    previous_width = 0
    for width, symbol in ordered:
        code <<= width - previous_width
        if code >= (1 << width):
            raise AssertionError("oversubscribed Huffman table")
        decoding[(width, code)] = symbol
        code += 1
        previous_width = width
    if code != (1 << previous_width):
        raise AssertionError("incomplete Huffman table")

    reader = _IndependentBitReader(payload[256:])

    def next_symbol() -> int:
        current = 0
        for width in range(1, 16):
            current = (current << 1) | reader.read(1)
            symbol = decoding.get((width, current))
            if symbol is not None:
                return symbol
        raise AssertionError("bitstream contains no valid symbol")

    output = bytearray()
    while len(output) < expected_size:
        symbol = next_symbol()
        if symbol < 256:
            output.append(symbol)
            continue

        match = symbol - 256
        encoded_length = match & 0x0F
        if encoded_length == 0x0F:
            raise AssertionError("extended match is outside the bounded profile")
        length = encoded_length + 3
        distance_bits = match >> 4
        distance = (1 << distance_bits) + reader.read(distance_bits)
        if distance > len(output):
            raise AssertionError("match precedes the output buffer")
        if len(output) + length > expected_size:
            raise AssertionError("match crosses expected output size")
        for _ in range(length):
            output.append(output[-distance])

    # XPRESS-Huffman itself has no EOF symbol. Symbol 256 is a normal
    # length-three/distance-one match that this bounded MAM profile deliberately
    # places after the declared output as a deterministic sentinel.
    if next_symbol() != 256:
        raise AssertionError("missing post-output sentinel")

    padding = (-reader.bit_position) % 16
    if reader.read(padding):
        raise AssertionError("nonzero post-output padding")
    if reader.remaining != 16 or reader.read(16):
        raise AssertionError("missing post-output zero lookahead word")
    return bytes(output)


def test_fixed_vector_round_trip_is_deterministic() -> None:
    source = (b"abc" * 200) + (b"XYZ" * 20)

    first = compress_xpress_huffman(source)
    second = compress_xpress_huffman(source)

    assert first == second
    assert len(first) == 274 < len(source)
    assert hashlib.sha256(first).hexdigest() == (
        "fc44c9d56ef87cb87ff557be05ab60f2f68689b0b2a70815311b5f162ba4cbc6"
    )
    assert _independent_decoder(first, len(source)) == source


@pytest.mark.parametrize(
    "source",
    [
        b"A" * 1_000,
        bytes(range(64)) * 30,
        (b"ArtifactForge-XPRESS-Huffman\x00" * 80) + bytes(range(32)),
    ],
)
def test_independent_decoder_round_trips_compressible_inputs(source: bytes) -> None:
    payload = compress_xpress_huffman(source)

    assert len(payload) < len(source)
    assert _independent_decoder(payload, len(source)) == source


@pytest.mark.parametrize("source", (b"A" * 1_000, bytes(range(64)) * 30))
def test_eof_driven_dissect_decoder_is_not_credited_with_exact_size(source: bytes) -> None:
    """Dissect ignores MAM's expected size and can expose profile padding."""
    from dissect.util.compression.lzxpress_huffman import decompress

    decoded = decompress(compress_xpress_huffman(source))

    assert decoded[: len(source)] == source
    assert len(decoded) == len(source) + 3


def test_profile_post_output_padding_and_lookahead_are_structurally_required() -> None:
    source = b"0123456789abcdef" * 100
    payload = compress_xpress_huffman(source)

    assert payload[-2:] == b"\x00\x00"
    assert _independent_decoder(payload, len(source)) == source

    nonzero_lookahead = payload[:-2] + b"\x00\x01"
    with pytest.raises(AssertionError, match="lookahead"):
        _independent_decoder(nonzero_lookahead, len(source))

    with pytest.raises(AssertionError, match="lookahead"):
        _independent_decoder(payload + b"\x00\x00", len(source))


def test_independent_decoder_rejects_malformed_table_and_wrong_size() -> None:
    source = b"abc" * 400
    payload = compress_xpress_huffman(source)

    with pytest.raises(AssertionError, match="empty Huffman table"):
        _independent_decoder((b"\x00" * 256) + payload[256:], len(source))
    with pytest.raises(AssertionError, match="expected output size"):
        _independent_decoder(payload, len(source) - 1)


def test_input_contract_and_expansion_refusal() -> None:
    with pytest.raises(TypeError, match="must be bytes"):
        compress_xpress_huffman(bytearray(b"A" * 1_000))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="must be bytes"):
        compress_xpress_huffman(memoryview(b"A" * 1_000))  # type: ignore[arg-type]
    with pytest.raises(XpressHuffmanError, match="must not be empty"):
        compress_xpress_huffman(b"")
    with pytest.raises(XpressHuffmanError, match="smaller than 64 KiB"):
        compress_xpress_huffman(b"A" * (MAX_CHUNK_SIZE + 1))
    with pytest.raises(XpressHuffmanError, match="not smaller"):
        compress_xpress_huffman(b"abc")


def test_maximum_chunk_boundary_round_trips() -> None:
    source = (b"0123456789abcdef" * 4_095) + b"0123456789abcde"
    assert len(source) == MAX_CHUNK_SIZE

    payload = compress_xpress_huffman(source)

    assert _independent_decoder(payload, MAX_CHUNK_SIZE) == source


def test_tokenizer_uses_greedy_overlapping_match_with_bounded_lengths() -> None:
    tokens = _tokenize(b"abcabcabcabc")

    assert tokens == (
        _Token(literal=ord("a")),
        _Token(literal=ord("b")),
        _Token(literal=ord("c")),
        _Token(length=9, distance=3),
    )
    assert all(
        token.is_literal or (3 <= token.length <= 17 and 1 <= token.distance <= 65_535)
        for token in tokens
    )


def test_match_symbol_boundaries_and_profile_sentinel_collision() -> None:
    # There is deliberately no standard terminal: the profile sentinel collides
    # with this ordinary match and is meaningful only after expected_size bytes.
    assert _token_symbol(_Token(length=3, distance=1)) == 256
    assert _token_symbol(_Token(length=17, distance=65_535)) == 510

    with pytest.raises(XpressHuffmanError, match="match length"):
        _token_symbol(_Token(length=18, distance=1))
    with pytest.raises(XpressHuffmanError, match="match distance"):
        _token_symbol(_Token(length=3, distance=65_536))


def test_pathological_dynamic_tree_uses_complete_nine_bit_fallback() -> None:
    first, second = 1, 1
    fibonacci = []
    for _ in range(18):
        fibonacci.append(first)
        first, second = second, first + second

    lengths = _bounded_code_lengths(dict(enumerate(fibonacci)))
    codes = _canonical_codes(lengths)

    assert lengths == (9,) * 512
    assert codes[0] == (0, 9)
    assert codes[-1] == (511, 9)


def test_canonical_table_rejects_incomplete_and_oversubscribed_lengths() -> None:
    with pytest.raises(XpressHuffmanError, match="incomplete"):
        _canonical_codes((1,) + (0,) * 511)
    with pytest.raises(XpressHuffmanError, match="oversubscribed"):
        _canonical_codes((1, 1, 1) + (0,) * 509)
