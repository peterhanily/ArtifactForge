# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Published prose carries protocol constants and scoped status, never attack scores.

Benchmark-v1 diagnostics were once copied into README prose and then drifted from their
scorecard.  V2 closes the class differently: machine-scoped verdicts are synchronized from the
committed card, protocol constants are checked against current provenance, and public-corpus
attack measurements remain unpublished diagnostics rather than performance claims.
"""
from fractions import Fraction
import json
import os
import re

import pytest

from artifactforge import suite

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CARD = os.path.join(ROOT, "fidelity-scorecard.json")
EF_RECORD = os.path.join(
    ROOT, "measurements", "evidenceforge-v1.13.1-branch-office-example.json"
)


@pytest.fixture(scope="module")
def card():
    with open(CARD) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def ef_record():
    with open(EF_RECORD) as f:
        return json.load(f)


def _read(rel):
    with open(os.path.join(ROOT, rel)) as f:
        return f.read()


def _percent(value: str) -> str:
    return f"{float(Fraction(value)):.0%}"


def test_readme_scoped_status_matches_the_committed_scorecard(card):
    text = _read("README.md")
    match = re.search(
        r"<!-- scorecard-status:start -->(.*?)<!-- scorecard-status:end -->",
        text,
        re.S,
    )
    assert match, "README is missing its generated scorecard status block"
    block = " ".join(match.group(1).split())
    assert f"(`{card['generator']['artifactforge_version']}`)" in block
    assert (
        f"Generator assurance is `{card['status']['generator_assurance']['verdict']}`" in block
    )
    assert (
        "experimental benchmark validity is "
        f"`{card['status']['benchmark_validity']['verdict']}`" in block
    )
    assert f"all-gates compatibility verdict is `{card['verdict']}`" in block
    assert "measurement corpus is explicitly non-reportable" in block


def test_benchmark_protocol_figures_are_derived_from_current_provenance():
    contract = suite.scorecard_measurement_provenance(40)["benchmark_contract"]
    questions = contract["questions"]
    inference = contract["inference"]
    controls = contract["shortcut_controls"]
    limits = contract["protocol"]["resource_limits"]
    text = " ".join(_read("docs/benchmark-v2.md").split())

    candidates = questions["candidates_per_question"]
    expected = (
        f"exact candidate chance is **{1 / candidates:.0%}**",
        f"**{inference['comparisons']} predeclared comparisons**",
        f"familywise alpha of **{_percent(inference['familywise_alpha'])}**",
        f"**{controls['mandatory_positive_controls']} mandatory positive controls**",
        f"At least **{inference['minimum_scenes_per_class']} scenes per family/rule class**",
        f"probability **{_percent(inference['alternative']['signal_probability'])}**",
        f"requires at least **{_percent(inference['target_power'])} power**",
        f"**1–{limits['maximum_scenarios']} scenarios**",
        f"**{limits['public_files_at_maximum']:,} files**",
        f"**{limits['recursive_file_limit']:,}-file**",
        f"**{limits['recursive_total_bytes_limit'] // (1024 * 1024)} MiB**",
        f"**{limits['public_json_bytes'] // (1024 * 1024)} MiB** public JSON",
        f"**{limits['answer_document_bytes'] // (1024 * 1024)} MiB** per answer document",
        f"**{limits['answer_value_characters']:,} characters**",
    )
    for statement in expected:
        assert statement in text, f"benchmark-v2 prose drifted from provenance: {statement!r}"


@pytest.mark.parametrize(
    "doc,anchor",
    (
        ("README.md", "V2 asks five scalar questions"),
        ("docs/benchmark-v2.md", "## Two roots with different roles"),
        ("docs/ROADMAP.md", "V2 replaces root-object questions"),
    ),
)
def test_current_v2_prose_does_not_publish_attack_or_solver_scores(doc, anchor):
    current = _read(doc).split(anchor, 1)[1]
    score_claim = re.search(
        r"(?:attack|adversary|shortcut|reference solver|rank|union)[^.\n]{0,100}"
        r"(?:score|accuracy)[^.\n]{0,40}\d+(?:\.\d+)?%",
        current,
        re.I,
    )
    assert score_claim is None, f"{doc} publishes a non-reportable v2 diagnostic: {score_claim}"


@pytest.mark.parametrize(
    "doc",
    ("docs/benchmark-v2.md", "SECURITY.md", "CHANGELOG.md"),
)
def test_withdrawn_v1_figures_appear_only_as_historical_invalidations(doc):
    text = _read(doc)
    for match in re.finditer(r"(?:72\.7|4\.2|20\.45)%", text):
        context = text[max(0, match.start() - 300) : match.end() + 300].lower()
        assert any(
            marker in context
            for marker in ("v1", "withdrawn", "invalid", "earlier", "historical")
        ), f"{doc} quotes {match.group()} outside an explicit v1 invalidation"


def test_public_evidenceforge_figures_are_bound_to_the_committed_measurement(ef_record):
    """Every duplicated EF count must be sourced from the provenance-bound JSON record."""
    results = ef_record["results"]
    sysmon = results["sysmon"]
    adapter = results["artifactforge_adapter_verification"]
    zeek = results["zeek_files"]
    forms = adapter["distinct_logical_identities_by_verified_seed_form"]
    expected = {
        "docs/evidenceforge.md": [
            f"{sysmon['host_logs']} hosts, {sysmon['hashed_records']} Sysmon records",
            f"all {adapter['records_recovered_and_verified']}\nrecovered and verified",
            f"resolving to {adapter['distinct_logical_identities']}\ndistinct",
            f"`from_host_metadata` for {forms['from_host_metadata']}\nidentities",
            f"`with_description` for {forms['with_description']}",
            f"Event ID 1 gives {sysmon['event_id_1']['hashed_records']} records",
            f"{zeek['rows']} rows: {zeek['certificate_rows']} certificate and "
            f"{zeek['non_certificate_rows']} non-certificate",
            f"{zeek['hashes']['sha1']['distinct']} distinct SHA1 and "
            f"{zeek['hashes']['sha256']['distinct']} distinct SHA256",
        ],
        "CHANGELOG.md": [
            f"{adapter['records_recovered_and_verified']} of "
            f"{sysmon['hashed_records']} Sysmon records",
            f"{adapter['distinct_logical_identities']} distinct Sysmon logical identities",
            f"split {forms['from_host_metadata']}\n`from_host_metadata` and "
            f"{forms['with_description']} `with_description`",
        ],
        "integration/evidenceforge/README.md": [
            f"| Hosts with Sysmon logs | {sysmon['host_logs']} |",
            f"| Sysmon records carrying SHA256 (Event IDs 1 and 7) | "
            f"{sysmon['hashed_records']} |",
            f"| Records whose Sysmon identity is recoverable and verified | "
            f"{adapter['records_recovered_and_verified']} (100%) |",
            f"| Event ID 1 only | {sysmon['event_id_1']['hashed_records']} records, "
            f"{sysmon['event_id_1']['distinct_hashes']['sha1']} distinct SHA1",
            f"has {zeek['rows']} rows, {zeek['hashes']['sha1']['distinct']} distinct SHA1 "
            f"values and {zeek['hashes']['sha256']['distinct']} distinct SHA256 values",
        ],
        "docs/ROADMAP.md": [
            f"has {zeek['rows']} rows, {zeek['certificate_rows']} certificate and "
            f"{zeek['non_certificate_rows']} non-certificate",
        ],
    }
    for doc, fragments in expected.items():
        text = _read(doc)
        for fragment in fragments:
            assert fragment in text, f"{doc} drifted from EF measurement: {fragment!r}"


def test_design_doc_scopes_a_green_gate_to_the_finite_registry():
    design = _read("docs/DESIGN.md")
    assert "finite registered attack/ensemble surface" in design
    assert "does not establish equivalence to candidate chance" in design
    assert "create a reportable public-corpus performance score" in design
