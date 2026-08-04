# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Benchmark v3 origin and evaluator-ceremony security boundary."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from fractions import Fraction
import hashlib
import inspect
import json
import os
from pathlib import Path
import shutil
import stat
import threading

import pytest

from artifactforge import cli, suite
from artifactforge.bench import benchmark
from artifactforge.bench import ceremony as ceremony_module
from artifactforge.bench.benchmark import generate_local_suite
from artifactforge.bench.ceremony import create_evaluator_ceremony
from artifactforge.bench.statistics import (
    SPARSE_POWER_SCENES_PER_FAMILY,
    sparse_permutation_power_contract,
)
from artifactforge.inventory import write_regular_file_at


pytest.importorskip("pefile")
pytest.importorskip("regipy")
pytest.importorskip("windowsprefetch")


@pytest.fixture(scope="module")
def ceremony_template(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("benchmark-v3") / "evaluator"
    original = suite.validate_benchmark_v3_scenario_count
    suite.validate_benchmark_v3_scenario_count = suite.validate_benchmark_scenario_count
    try:
        create_evaluator_ceremony(1, os.fspath(root))
    finally:
        suite.validate_benchmark_v3_scenario_count = original
    return root


@pytest.fixture
def evaluator(tmp_path, ceremony_template, monkeypatch) -> Path:
    monkeypatch.setattr(
        suite,
        "validate_benchmark_v3_scenario_count",
        suite.validate_benchmark_scenario_count,
    )
    root = tmp_path / "evaluator"
    shutil.copytree(ceremony_template, root)
    return root


@pytest.fixture
def tiny_v3(monkeypatch):
    monkeypatch.setattr(
        suite,
        "validate_benchmark_v3_scenario_count",
        suite.validate_benchmark_scenario_count,
    )


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_canonical(path: Path, document: dict) -> None:
    path.write_bytes(suite.canonical_public_bytes(document))


def _rebind_public(root: Path, mutate) -> dict:
    path = root / "public.json"
    document = _read_json(path)
    base = {
        key: value
        for key, value in document.items()
        if key not in {"public_export", "schema", "suite_id"}
    }
    mutate(base)
    rebound = suite.build_public_document(base, root / "scenarios")
    _write_canonical(path, rebound)
    return rebound


def test_v2_is_preserved_as_permanently_ineligible_local_protocol(tmp_path):
    root = tmp_path / "legacy"
    generate_local_suite(
        1,
        os.fspath(root),
        key=bytes.fromhex("a4" * 32),
        kind=suite.HOLDOUT_SUITE_KIND,
    )
    document = suite.load_evaluator_public(os.fspath(root))

    assert document["schema"] == suite.PUBLIC_DOCUMENT_SCHEMA_V2
    assert document["domain"] == suite.DOMAIN.decode()
    assert "origin" not in document
    assert not (root / "_ceremony").exists()
    assert suite.benchmark_reportability(document) == suite.REPORTABILITY_PERMANENTLY_INELIGIBLE


@pytest.mark.parametrize("count", (1, 119, 121, 199, 201))
def test_v3_refuses_unqualified_population_before_entropy_or_destination_mutation(
    tmp_path, monkeypatch, count
):
    destination = tmp_path / f"invalid-{count}"

    def entropy_must_not_be_requested(_count):
        raise AssertionError("invalid v3 population reached the entropy source")

    monkeypatch.setattr(ceremony_module.secrets, "token_bytes", entropy_must_not_be_requested)
    with pytest.raises(ValueError, match="v3 ceremony size|between 1 and 200"):
        create_evaluator_ceremony(count, os.fspath(destination))
    assert not destination.exists()


@pytest.mark.parametrize("count", (120, 122, 200))
def test_v3_accepts_only_balanced_qualified_population_values(count):
    assert suite.validate_benchmark_v3_scenario_count(count) == count


def test_cli_rejects_unbalanced_v3_population_before_creation(tmp_path, capsys):
    destination = tmp_path / "invalid-cli"
    with pytest.raises(SystemExit) as raised:
        cli.main(
            [
                "bench",
                "ceremony",
                "create",
                os.fspath(destination),
                "--n",
                "121",
            ]
        )
    assert raised.value.code == 2
    assert "even integer between 120 and 200" in capsys.readouterr().err
    assert not destination.exists()


def test_ceremony_api_exposes_no_key_or_origin_parameters(evaluator):
    assert tuple(inspect.signature(create_evaluator_ceremony).parameters) == ("n", "root")
    document = suite.load_evaluator_public(os.fspath(evaluator))
    origin = document["origin"]

    assert document["schema"] == suite.PUBLIC_DOCUMENT_SCHEMA_V3
    assert document["domain"] == suite.BENCHMARK_V3_DOMAIN.decode()
    assert origin["mode"] == suite.BENCHMARK_CEREMONY_MODE
    assert origin["reportability"] == suite.REPORTABILITY_PENDING_EXTERNAL_ATTESTATION
    assert "LOCAL SELF-ATTESTATION ONLY" in origin["trust"]
    assert suite.benchmark_reportability(document) == origin["reportability"]


def test_theoretical_population_power_contract_is_bound_into_suite_id(evaluator):
    document = suite.load_evaluator_public(os.fspath(evaluator))
    contract = document["origin"]["protocol"]["population_power_contract"]
    exact = sparse_permutation_power_contract(60, comparisons=39)

    assert suite.BENCHMARK_V3_MIN_SCENES_PER_FAMILY == SPARSE_POWER_SCENES_PER_FAMILY == 60
    assert contract == suite.benchmark_v3_protocol_identity()["population_power_contract"]
    assert contract["comparisons"] == exact.comparisons == 39
    assert Fraction(contract["familywise_alpha"]) == exact.familywise_alpha
    assert Fraction(contract["adjusted_per_comparison_alpha"]) == exact.adjusted_alpha
    assert Fraction(contract["null_upper_tail_at_60_scenes"]) == exact.null_upper_tail
    assert contract["critical_hits_at_60_scenes"] == exact.critical_hits
    assert Fraction(contract["target_power"]) == exact.target_power
    for declared, measured in zip(contract["alternatives"], exact.alternatives, strict=True):
        assert declared["name"] == measured.name
        assert declared["model"] == measured.model
        assert Fraction(declared["signal_probability"]) == measured.signal_probability
        assert Fraction(declared["power_at_60_scenes"]) == measured.power
        assert declared["first_scenes_meeting_target"] == measured.minimum_scenes_for_target
    unsigned = json.loads(json.dumps(document))
    original_suite_id = unsigned.pop("suite_id")
    unsigned["origin"]["protocol"]["population_power_contract"][
        "minimum_scenes_per_family"
    ] = 61
    mutated_suite_id = (
        "sha256:" + hashlib.sha256(suite.canonical_public_bytes(unsigned)).hexdigest()
    )
    assert mutated_suite_id != original_suite_id


def test_ceremony_internally_mints_key_and_identifier_material(tmp_path, monkeypatch, tiny_v3):
    material = bytes(range(48))
    requested = []
    real_token_bytes = ceremony_module.secrets.token_bytes

    def token_bytes(count):
        requested.append(count)
        if requested == [48]:
            return material
        return real_token_bytes(count)

    monkeypatch.setattr(ceremony_module.secrets, "token_bytes", token_bytes)
    monkeypatch.setattr(ceremony_module, "_created_at", lambda: "2026-08-03T12:34:56.000000Z")
    root = tmp_path / "deterministic-ceremony"
    create_evaluator_ceremony(1, os.fspath(root))
    document = suite.load_evaluator_public(os.fspath(root))

    assert requested[0] == 48
    assert (root / "_key" / "key.hex").read_text(encoding="ascii") == material[:32].hex()
    assert document["origin"]["ceremony_id"] == suite.ceremony_id_from_entropy(material[32:])
    assert document["origin"]["key_commitment"] == suite.ceremony_key_commitment(material[:32])


def test_origin_is_bound_into_suite_id(evaluator):
    public_path = evaluator / "public.json"
    document = _read_json(public_path)
    document["origin"]["trust"] += " mutated"
    _write_canonical(public_path, document)

    with pytest.raises(ValueError, match="suite_id does not bind"):
        suite.load_evaluator_public(os.fspath(evaluator))


@pytest.mark.parametrize(
    ("mutate", "match"),
    (
        (lambda origin: origin.update({"mode": "raw-local"}), "origin mode"),
        (
            lambda origin: origin.update({"reportability": "reportable"}),
            "reportability classification",
        ),
        (
            lambda origin: origin["protocol"].update({"domain": suite.DOMAIN.decode()}),
            "protocol identity",
        ),
        (lambda origin: origin.update({"created_at": "2026-02-31T00:00:00.000000Z"}), "real UTC"),
        (lambda origin: origin.update({"unknown": True}), "exact ceremony field set"),
    ),
)
def test_origin_rejects_structural_and_model_mutation(evaluator, mutate, match):
    document = _read_json(evaluator / "public.json")
    base = {
        key: value
        for key, value in document.items()
        if key not in {"public_export", "schema", "suite_id"}
    }
    mutate(base["origin"])
    with pytest.raises(ValueError, match=match):
        suite.build_public_document(base, evaluator / "scenarios")


def test_private_record_wrong_ceremony_id_is_rejected(evaluator):
    record_path = evaluator / "_ceremony" / "ceremony.json"
    record = _read_json(record_path)
    record["ceremony_id"] = "afc1_" + "a" * 26
    _write_canonical(record_path, record)

    with pytest.raises(ValueError, match="does not equal the bound public origin"):
        suite.load_evaluator_public(os.fspath(evaluator))


def test_wrong_key_commitment_is_rejected_even_when_public_and_private_agree(evaluator):
    wrong = "sha256:" + "0" * 64
    record_path = evaluator / "_ceremony" / "ceremony.json"
    record = _read_json(record_path)
    record["key_commitment"] = wrong
    _write_canonical(record_path, record)
    _rebind_public(evaluator, lambda base: base["origin"].update({"key_commitment": wrong}))

    with pytest.raises(ValueError, match="key commitment does not match evaluator key"):
        suite.load_evaluator_public(os.fspath(evaluator))


def test_private_record_rejects_unknown_fields(evaluator):
    record_path = evaluator / "_ceremony" / "ceremony.json"
    record = _read_json(record_path)
    record["unknown"] = "not allowed"
    _write_canonical(record_path, record)

    with pytest.raises(ValueError, match="exact ceremony field set"):
        suite.load_evaluator_public(os.fspath(evaluator))


def test_private_record_symlink_is_rejected(evaluator, tmp_path):
    record_path = evaluator / "_ceremony" / "ceremony.json"
    external = tmp_path / "external.json"
    external.write_bytes(record_path.read_bytes())
    record_path.unlink()
    record_path.symlink_to(external)

    with pytest.raises(ValueError, match="regular file|link|safely read"):
        suite.load_evaluator_public(os.fspath(evaluator))


def test_private_record_same_byte_replacement_is_detected(evaluator, monkeypatch):
    original = suite._read_regular_at
    replaced = False

    def replace_after_first_read(parent_fd, name, where, *, max_bytes=None):
        nonlocal replaced
        data = original(parent_fd, name, where, max_bytes=max_bytes)
        if where == "evaluator ceremony record" and not replaced:
            replaced = True
            os.unlink(name, dir_fd=parent_fd)
            write_regular_file_at(parent_fd, name, data, mode=0o600)
        return data

    monkeypatch.setattr(suite, "_read_regular_at", replace_after_first_read)
    with pytest.raises(ValueError, match="ceremony record changed"):
        suite.load_evaluator_public(os.fspath(evaluator))
    assert replaced


def test_ceremony_publication_refuses_preexisting_symlink(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    sentinel = target / "preserve"
    sentinel.write_text("preserve", encoding="utf-8")
    destination = tmp_path / "evaluator"
    destination.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="pre-existing evaluator suite destination"):
        create_evaluator_ceremony(suite.BENCHMARK_V3_MIN_SCENARIOS, os.fspath(destination))
    assert destination.is_symlink()
    assert sentinel.read_text(encoding="utf-8") == "preserve"


def test_existing_ceremony_cannot_be_reused_or_replaced(evaluator):
    before = (evaluator / "public.json").read_bytes()
    with pytest.raises(ValueError, match="pre-existing evaluator suite destination"):
        create_evaluator_ceremony(1, os.fspath(evaluator))
    assert (evaluator / "public.json").read_bytes() == before
    suite.load_evaluator_public(os.fspath(evaluator))


def test_hostile_umask_cannot_weaken_or_remove_private_modes(tmp_path, tiny_v3):
    if os.name == "nt":
        pytest.skip("POSIX modes do not apply on Windows")
    root = tmp_path / "evaluator"
    previous = os.umask(0o777)
    try:
        create_evaluator_ceremony(1, os.fspath(root))
    finally:
        os.umask(previous)

    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "_ceremony").stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "_key").stat().st_mode) == 0o700
    for path in (
        root / "public.json",
        root / "_ceremony" / "ceremony.json",
        root / "_key" / "key.hex",
    ):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    suite.load_evaluator_public(os.fspath(root))


@pytest.mark.parametrize(
    ("relative", "mode", "match"),
    (
        (".", 0o755, "ceremony root mode"),
        ("_ceremony", 0o755, "ceremony directory mode"),
        ("_ceremony/ceremony.json", 0o644, "ceremony record mode"),
        ("_key", 0o755, "key directory mode"),
        ("_key/key.hex", 0o644, "evaluator key mode"),
    ),
)
def test_ceremony_loader_rejects_non_private_modes(evaluator, relative, mode, match):
    if os.name == "nt":
        pytest.skip("POSIX modes do not apply on Windows")
    os.chmod(evaluator / relative, mode)
    with pytest.raises(ValueError, match=match):
        suite.load_evaluator_public(os.fspath(evaluator))


def test_concurrent_creation_publishes_exactly_one_verified_ceremony(
    tmp_path, monkeypatch, tiny_v3
):
    destination = tmp_path / "shared"
    barrier = threading.Barrier(2)
    original = benchmark.rename_directory_no_replace

    def synchronized_publish(source, output, **kwargs):
        if Path(output).name == destination.name:
            barrier.wait(timeout=20)
        return original(source, output, **kwargs)

    monkeypatch.setattr(benchmark, "rename_directory_no_replace", synchronized_publish)

    def create():
        try:
            create_evaluator_ceremony(1, os.fspath(destination))
        except ValueError as exc:
            return "error", str(exc)
        return "ok", ""

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = [
            future.result(timeout=30)
            for future in (executor.submit(create), executor.submit(create))
        ]

    assert [status for status, _message in results].count("ok") == 1
    assert [status for status, _message in results].count("error") == 1
    assert "destination that appeared" in next(
        message for status, message in results if status == "error"
    )
    suite.load_evaluator_public(os.fspath(destination))
    assert not tuple(tmp_path.glob(".shared.stage-*"))


def test_public_export_omits_private_ceremony_state(evaluator, tmp_path):
    public = tmp_path / "public"
    suite.export_public(os.fspath(evaluator), os.fspath(public))
    document = suite.load_public_export(os.fspath(public))

    assert document["schema"] == suite.PUBLIC_DOCUMENT_SCHEMA_V3
    assert document["origin"]["ceremony_id"]
    assert not (public / "_ceremony").exists()
    assert not (public / "_key").exists()


def test_cli_ceremony_create_is_usable_and_does_not_print_key_material(tmp_path, capsys):
    root = tmp_path / "cli-evaluator"
    assert cli.main(["bench", "ceremony", "create", os.fspath(root)]) == 0
    output = capsys.readouterr().out
    document = suite.load_evaluator_public(os.fspath(root))

    assert "benchmark v3 evaluator ceremony" in output
    assert len(document["scenarios"]) == suite.BENCHMARK_V3_MIN_SCENARIOS == 120
    assert document["origin"]["ceremony_id"] in output
    assert document["suite_id"] in output
    assert (root / "_key" / "key.hex").read_text(encoding="ascii") not in output
    assert "not itself a reportable result" in output

    public = tmp_path / "cli-public"
    suite.export_public(os.fspath(root), os.fspath(public))
    loaded = suite.load_public_export(os.fspath(public))
    assert loaded["suite_id"] == document["suite_id"]
    assert len(loaded["scenarios"]) == 120
