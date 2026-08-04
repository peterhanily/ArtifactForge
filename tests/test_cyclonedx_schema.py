# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Official CycloneDX validation is offline, hash-pinned and hostile-input bounded."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "artifactforge_validate_cyclonedx",
    ROOT / "scripts" / "validate_cyclonedx.py",
)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)

OFFICIAL_COMMIT = "c320fc0f0b46873864927d9d5684eea7ba439728"
OFFICIAL_HASHES = {
    "bom-1.5.schema.json": "067f7824b08653839ea050ae9e09ca48375eadc2652b0e2a299476e7db90335b",
    "jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
    "spdx.schema.json": "4f6e2b05c05d26a4f2dc5879fbc2fca94b0a28db46289d0c51345621b71cfbfc",
}


def _canonical(document: object) -> bytes:
    return (
        json.dumps(
            document, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        )
        + "\n"
    ).encode()


def _schema_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "schemas"
    directory.mkdir()
    documents = {
        "bom-1.5.schema.json": {
            "$id": validator.SCHEMA_IDENTIFIERS["bom-1.5.schema.json"],
            "$schema": "http://json-schema.org/draft-07/schema#",
            "additionalProperties": False,
            "properties": {
                "bomFormat": {"const": "CycloneDX"},
                "license": {"$ref": "spdx.schema.json#/definitions/license"},
                "signature": {"$ref": "jsf-0.82.schema.json#/definitions/signature"},
                "specVersion": {"const": "1.5"},
                "version": {"const": 1},
            },
            "required": ["bomFormat", "license", "signature", "specVersion", "version"],
            "type": "object",
        },
        "jsf-0.82.schema.json": {
            "$id": validator.SCHEMA_IDENTIFIERS["jsf-0.82.schema.json"],
            "$schema": "http://json-schema.org/draft-07/schema#",
            "definitions": {
                "signature": {
                    "additionalProperties": False,
                    "properties": {"algorithm": {"const": "fixture"}},
                    "required": ["algorithm"],
                    "type": "object",
                }
            },
        },
        "spdx.schema.json": {
            "$id": validator.SCHEMA_IDENTIFIERS["spdx.schema.json"],
            "$schema": "http://json-schema.org/draft-07/schema#",
            "definitions": {"license": {"const": "MIT", "type": "string"}},
        },
    }
    hashes = {}
    for name, document in documents.items():
        payload = _canonical(document)
        (directory / name).write_bytes(payload)
        hashes[name] = hashlib.sha256(payload).hexdigest()
    monkeypatch.setattr(validator, "EXPECTED_SCHEMA_SHA256", hashes)
    return directory


def _valid_sbom(path: Path, *, suffix: str = "") -> Path:
    path.write_bytes(
        _canonical(
            {
                "bomFormat": "CycloneDX",
                "license": "MIT",
                "signature": {"algorithm": "fixture"},
                "specVersion": "1.5",
                "version": 1,
            }
        )
        + suffix.encode()
    )
    return path


def test_official_1_5_schema_source_and_hashes_are_exact_reviewed_values() -> None:
    assert validator.CYCLONEDX_SPECIFICATION_COMMIT == OFFICIAL_COMMIT
    assert validator.CYCLONEDX_SCHEMA_BASE_URL == (
        f"https://raw.githubusercontent.com/CycloneDX/specification/{OFFICIAL_COMMIT}/schema"
    )
    assert validator.EXPECTED_SCHEMA_SHA256 == OFFICIAL_HASHES


def test_three_distinct_sboms_validate_through_both_offline_references(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    schemas = _schema_directory(tmp_path, monkeypatch)
    sboms = tuple(_valid_sbom(tmp_path / f"subject-{index}.cdx.json") for index in range(3))

    assert validator.main(["--schema-dir", str(schemas), *(str(path) for path in sboms)]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.count("CycloneDX 1.5 schema PASS:") == 3


@pytest.mark.parametrize(
    "mutation",
    ["missing", "extra", "directory", "symlink", "tampered", "oversized"],
)
def test_schema_set_must_be_exact_regular_bounded_and_hash_pinned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mutation: str,
) -> None:
    schemas = _schema_directory(tmp_path, monkeypatch)
    target = schemas / "spdx.schema.json"
    if mutation == "missing":
        target.unlink()
    elif mutation == "extra":
        (schemas / "unreviewed.schema.json").write_text("{}")
    elif mutation == "directory":
        target.unlink()
        target.mkdir()
    elif mutation == "symlink":
        outside = tmp_path / "outside.schema.json"
        outside.write_bytes(target.read_bytes())
        target.unlink()
        try:
            target.symlink_to(outside)
        except OSError as exc:  # pragma: no cover - Windows developer-mode dependent
            pytest.skip(f"symlinks are unavailable: {exc}")
    elif mutation == "tampered":
        target.write_bytes(target.read_bytes() + b" ")
    else:
        monkeypatch.setattr(validator, "MAX_SCHEMA_BYTES", 32)
    sbom = _valid_sbom(tmp_path / "subject.cdx.json")

    assert validator.main(["--schema-dir", str(schemas), str(sbom)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("cyclonedx-schema: error:")
    assert "Traceback" not in captured.err


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b"{", "strict UTF-8 JSON"),
        (b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}', "duplicate"),
        (b'{"bomFormat":"CycloneDX","version":NaN}', "non-finite"),
        (b'{"version":' + (b"1" * 5_000) + b"}", "signed 64-bit"),
        (b'{"version":1e999999}', "floating-point values are forbidden"),
        (b'{"version":1.0}', "floating-point values are forbidden"),
        (b'{"name":"\\ud800"}', "lone Unicode surrogate"),
        (b"[]", "root must be a JSON object"),
        (b'{"nested":' + (b"[" * 130) + b"0" + (b"]" * 130) + b"}", "nesting limit"),
        (_canonical({"bomFormat": "not-cyclonedx"}), "official CycloneDX 1.5 schema"),
    ],
)
def test_hostile_or_invalid_sbom_is_an_exit_2_without_a_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    payload: bytes,
    message: str,
) -> None:
    schemas = _schema_directory(tmp_path, monkeypatch)
    sbom = tmp_path / "hostile.cdx.json"
    sbom.write_bytes(payload)

    assert validator.main(["--schema-dir", str(schemas), str(sbom)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert message in captured.err
    assert "Traceback" not in captured.err


def test_json_integer_profile_accepts_only_the_signed_64_bit_boundaries() -> None:
    minimum = validator._decode_json(
        b'{"value":-9223372036854775808}',
        label="minimum fixture",
    )
    maximum = validator._decode_json(
        b'{"value":9223372036854775807}',
        label="maximum fixture",
    )
    assert minimum == {"value": -(1 << 63)}
    assert maximum == {"value": (1 << 63) - 1}
    with pytest.raises(validator.CycloneDXSchemaError, match="signed 64-bit"):
        validator._decode_json(b'{"value":-9223372036854775809}', label="underflow fixture")
    with pytest.raises(validator.CycloneDXSchemaError, match="signed 64-bit"):
        validator._decode_json(b'{"value":9223372036854775808}', label="overflow fixture")


@pytest.mark.parametrize("mutation", ["empty", "directory", "symlink", "oversized"])
def test_sbom_input_must_be_a_bounded_nonempty_regular_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mutation: str,
) -> None:
    schemas = _schema_directory(tmp_path, monkeypatch)
    sbom = tmp_path / "subject.cdx.json"
    if mutation == "empty":
        sbom.write_bytes(b"")
    elif mutation == "directory":
        sbom.mkdir()
    elif mutation == "symlink":
        outside = _valid_sbom(tmp_path / "outside.cdx.json")
        try:
            sbom.symlink_to(outside)
        except OSError as exc:  # pragma: no cover - Windows developer-mode dependent
            pytest.skip(f"symlinks are unavailable: {exc}")
    else:
        _valid_sbom(sbom)
        monkeypatch.setattr(validator, "MAX_SBOM_BYTES", 8)

    assert validator.main(["--schema-dir", str(schemas), str(sbom)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("cyclonedx-schema: error:")
    assert "Traceback" not in captured.err


@pytest.mark.parametrize("alias_kind", ["same-path", "hard-link"])
def test_repeated_sbom_identity_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    alias_kind: str,
) -> None:
    schemas = _schema_directory(tmp_path, monkeypatch)
    sbom = _valid_sbom(tmp_path / "subject.cdx.json")
    if alias_kind == "same-path":
        alias = sbom
    else:
        alias = tmp_path / "alias.cdx.json"
        try:
            os.link(sbom, alias)
        except OSError as exc:  # pragma: no cover - filesystem dependent
            pytest.skip(f"hard links are unavailable: {exc}")
    assert validator.main(["--schema-dir", str(schemas), str(sbom), str(alias)]) == 2


def test_both_release_evidence_lanes_fetch_hash_check_and_validate_all_three_sboms() -> None:
    expected_names = (
        "bom-1.5.schema.json",
        "jsf-0.82.schema.json",
        "spdx.schema.json",
    )
    expected_sboms = (
        "sbom/wheel.cdx.json",
        "sbom/sdist.cdx.json",
        "sbom/development-oracles.cdx.json",
    )
    for relative in (".github/workflows/ci.yml", ".github/workflows/release-evidence.yml"):
        text = (ROOT / relative).read_text()
        assert f'CYCLONEDX_SCHEMA_COMMIT: "{OFFICIAL_COMMIT}"' in text
        assert (
            "https://raw.githubusercontent.com/CycloneDX/specification/"
            "${CYCLONEDX_SCHEMA_COMMIT}/schema/${SCHEMA_NAME}"
        ) in text
        assert text.count("scripts/validate_cyclonedx.py") == 1
        for name in expected_names:
            assert name in text
            assert OFFICIAL_HASHES[name] in text
        for sbom in expected_sboms:
            assert sbom in text
        hash_check = text.index("sha256sum --check --strict")
        schema_check = text.index("scripts/validate_cyclonedx.py")
        assert hash_check < schema_check
