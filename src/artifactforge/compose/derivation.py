# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Closed scene-local derivation policies.

Scene construction needs two independent kinds of deterministic entropy: values which choose
and order incident facts, and seeds which determine emitted content bytes.  Keeping both in
one implicit benchmark namespace made it impossible for Fixture Core to evolve its recipe
without silently inheriting the benchmark ABI.

The benchmark policy below is a compatibility boundary.  Its formulas exactly reproduce the
historic :mod:`artifactforge.suite` ``scene_value``, ``pick``, ``pick_many`` and
``content_seed`` functions.  Fixture v2 deliberately uses different value and content
domains, so neither corpus can accidentally reproduce the other under the same scene key.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
from typing import TypeVar, final


BENCHMARK_VALUE_DOMAIN = "artifactforge/bench/v1"
BENCHMARK_CONTENT_DOMAIN = "artifactforge/bench/v1"
FIXTURE_V2_VALUE_DOMAIN = "artifactforge/fixture/scene-value/v2"
FIXTURE_V2_CONTENT_DOMAIN = "artifactforge/fixture/content-derivation/v2"
DERIVATION_ALGORITHM = "hmac-sha256-unit-separator-v1"

_SEPARATOR = b"\x1f"
_SEPARATOR_TEXT = "\x1f"
_T = TypeVar("_T")


def _text(value: object, what: str) -> str:
    if type(value) is not str or not value or _SEPARATOR_TEXT in value:
        raise ValueError(f"{what} must be a non-empty string without the unit separator")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise ValueError(f"{what} must be valid UTF-8 text") from error
    return value


def _domain(value: object, what: str) -> str:
    domain = _text(value, what)
    try:
        encoded = domain.encode("ascii", errors="strict")
    except UnicodeError as error:
        raise ValueError(f"{what} must be ASCII") from error
    if len(encoded) > 128:
        raise ValueError(f"{what} must be at most 128 ASCII bytes")
    return domain


@final
@dataclass(frozen=True, slots=True)
class SceneDerivation:
    """One immutable, explicit scene derivation contract.

    ``value_domain`` controls selections, permutations and scalar scene facts.
    ``content_domain`` controls only content-store seeds and content-derived opaque tokens.
    The two fields may intentionally be equal for a frozen compatibility policy, but callers
    never have to infer that coupling from an unrelated suite module.
    """

    name: str
    value_domain: str
    content_domain: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _domain(self.name, "derivation name"))
        object.__setattr__(
            self, "value_domain", _domain(self.value_domain, "scene value domain")
        )
        object.__setattr__(
            self, "content_domain", _domain(self.content_domain, "scene content domain")
        )

    @property
    def provenance(self) -> dict[str, str]:
        """A fresh JSON-ready record of the complete derivation identity."""
        return {
            "name": self.name,
            "algorithm": DERIVATION_ALGORITHM,
            "value_domain": self.value_domain,
            "content_domain": self.content_domain,
            "content_prefix": "content",
        }

    @staticmethod
    def validate_key(skey: object) -> bytes:
        """Return one exact scene key or fail before any derivation occurs."""
        if type(skey) is not bytes or len(skey) != 32:
            raise ValueError("scene key must be exactly 32 bytes")
        return skey

    @staticmethod
    def _parts(parts: tuple[object, ...], what: str) -> tuple[str, ...]:
        if not parts:
            raise ValueError(f"{what} requires at least one derivation part")
        return tuple(_text(part, f"{what} part") for part in parts)

    def _derive(self, skey: object, domain: str, parts: tuple[object, ...], what: str) -> bytes:
        key = self.validate_key(skey)
        labels = self._parts(parts, what)
        message = domain.encode("ascii") + _SEPARATOR + _SEPARATOR.join(
            label.encode("utf-8") for label in labels
        )
        return hmac.new(key, message, hashlib.sha256).digest()

    def value(self, skey: object, *parts: object) -> bytes:
        """Derive one scene-local value under ``value_domain``."""
        return self._derive(skey, self.value_domain, parts, "scene value")

    def content_seed(self, skey: object, role: object) -> str:
        """Return the hexadecimal ContentStore seed for one exact semantic role."""
        return self._derive(
            skey,
            self.content_domain,
            ("content", _text(role, "content role")),
            "content seed",
        ).hex()

    @staticmethod
    def _pool(pool: object) -> tuple[str, ...]:
        if type(pool) not in (list, tuple) or not pool:
            raise ValueError("derivation pool must be a non-empty list or tuple")
        values = tuple(_text(value, "derivation pool member") for value in pool)
        if len(set(values)) != len(values):
            raise ValueError("derivation pool members must be unique")
        return values

    def pick(self, skey: object, field: object, pool: object) -> str:
        """Choose one member using the frozen benchmark-compatible value formula."""
        label = _text(field, "pick field")
        values = self._pool(pool)
        index = int.from_bytes(self.value(skey, "pick", label)[:4], "big") % len(values)
        return values[index]

    def pick_many(self, skey: object, field: object, pool: object, count: object) -> list[str]:
        """Choose ``count`` distinct members in their deterministic keyed rank order."""
        label = _text(field, "pick-many field")
        values = self._pool(pool)
        if type(count) is not int or count < 1 or count > len(values):
            raise ValueError("pick-many count must be an integer within the pool")
        ranked = sorted(
            values,
            key=lambda value: self.value(skey, f"{label}:rank", str(value)),
        )
        return ranked[:count]

    def order(
        self,
        skey: object,
        label: object,
        values: object,
        *,
        identity: Callable[[_T], object],
    ) -> list[_T]:
        """Order objects by unique public identities in one independent value subdomain."""
        order_label = _text(label, "scene order label")
        if type(values) not in (list, tuple) or not values:
            raise ValueError("scene order values must be a non-empty list or tuple")
        if not callable(identity):
            raise ValueError("scene order identity must be callable")
        decorated = []
        identities = set()
        ranks = set()
        for value in values:
            item_identity = _text(identity(value), "scene order identity")
            if item_identity in identities:
                raise ValueError("scene order identities must be unique")
            identities.add(item_identity)
            rank = self.value(skey, f"scene-order:{order_label}:{item_identity}")
            if rank in ranks:  # Cryptographically implausible, but ordering must fail closed.
                raise ValueError("scene order derived ranks collided")
            ranks.add(rank)
            decorated.append((rank, value))
        return [value for _rank, value in sorted(decorated, key=lambda item: item[0])]

    def bounded_key_value(
        self,
        skey: object,
        label: object,
        *,
        key_index: object,
        modulus: object,
        offset: object = 0,
    ) -> int:
        """Derive a bounded scalar while preserving benchmark v1's direct-key formula.

        The old benchmark used four key bytes directly for prefetch run counts.  That oddity
        is part of its byte ABI.  Non-benchmark value domains use a labelled HMAC instead, so
        Fixture v2 has no undeclared benchmark-local value channel.
        """
        key = self.validate_key(skey)
        scalar_label = _text(label, "bounded value label")
        if type(key_index) is not int or key_index < 0 or key_index >= len(key):
            raise ValueError("bounded value key index must name one scene-key byte")
        if type(modulus) is not int or modulus < 1:
            raise ValueError("bounded value modulus must be a positive integer")
        if type(offset) is not int:
            raise ValueError("bounded value offset must be an integer")
        if self.value_domain == BENCHMARK_VALUE_DOMAIN:
            entropy = key[key_index]
        else:
            entropy = int.from_bytes(
                self.value(key, "bounded-key-value", scalar_label, str(key_index))[:4], "big"
            )
        return offset + entropy % modulus

    def opaque_sha1(self, skey: object, label: object) -> str:
        """Derive a hash-shaped absent identity without creating a content join.

        Benchmark v1 used ``SHA1(skey || label)`` and that exact output remains frozen.  A
        different value domain uses labelled domain-separated entropy before SHA-1 shaping.
        SHA-1 is intentionally only the synthetic identity algorithm here, never security.
        """
        key = self.validate_key(skey)
        text = _text(label, "opaque SHA1 label")
        if self.value_domain == BENCHMARK_VALUE_DOMAIN:
            material = key + text.encode("utf-8")
        else:
            material = self.value(key, "opaque-sha1", text)
        return hashlib.sha1(material).hexdigest()  # noqa: S324 - synthetic file identity


BENCHMARK_SCENE_DERIVATION = SceneDerivation(
    name="artifactforge/benchmark-scene-derivation/v1",
    value_domain=BENCHMARK_VALUE_DOMAIN,
    content_domain=BENCHMARK_CONTENT_DOMAIN,
)

FIXTURE_V2_SCENE_DERIVATION = SceneDerivation(
    name="artifactforge/fixture-scene-derivation/v2",
    value_domain=FIXTURE_V2_VALUE_DOMAIN,
    content_domain=FIXTURE_V2_CONTENT_DOMAIN,
)


__all__ = [
    "BENCHMARK_CONTENT_DOMAIN",
    "BENCHMARK_SCENE_DERIVATION",
    "BENCHMARK_VALUE_DOMAIN",
    "DERIVATION_ALGORITHM",
    "FIXTURE_V2_CONTENT_DOMAIN",
    "FIXTURE_V2_SCENE_DERIVATION",
    "FIXTURE_V2_VALUE_DOMAIN",
    "SceneDerivation",
]
