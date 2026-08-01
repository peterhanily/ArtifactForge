# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Every figure quoted in prose must be the one the committed scorecard holds.

This exists because the documentation drifted from the measurement in the single worst place
it could have: the README published a chance floor of 3.7% while `fidelity-scorecard.json`
said 4.1%, five lines above the sentence "the committed scorecard is the number of record —
quoting a different run's figure here is how a document starts lying slowly". Nobody had
lied; the scorecard was regenerated twice after the prose was pinned to it, and prose does not
regenerate. That is exactly how a document starts lying slowly.

Updating the number would have fixed the instance. This fixes the class: the two can no longer
diverge without a test going red, so the figures in the README are as maintained as the code.

The check runs in both directions on purpose. A missing figure means the prose stopped citing
something it should; an *extra* percentage in the benchmark section means a number appeared
from somewhere other than the scorecard, which is the failure that actually happened.
"""
import json
import os
import re

import pytest

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


def _published(card):
    """The figures the prose is allowed to quote, rendered the way prose renders them."""
    s = card["gates"]["solvability"]
    return {
        "reference solver": f"{s['reference_solver_score']:.0%}",
        "footprint adversary": f"{s['footprint_solver_score']:.1%}",
        "chance floor": f"{s['chance_floor']:.1%}",
    }


def _benchmark_section(text):
    """The 'Benchmark validity' paragraph — the one whose whole job is being checkable."""
    start = text.index("**Benchmark validity")
    rest = text[start:]
    end = rest.find("\n**")
    return rest[: end if end > 0 else len(rest)]


@pytest.mark.parametrize("doc", ["README.md", "docs/ROADMAP.md"])
def test_every_published_figure_matches_the_committed_scorecard(card, doc):
    text = _read(doc)
    for label, rendered in _published(card).items():
        assert rendered in text, (
            f"{doc} does not quote the committed {label} ({rendered}). Either the scorecard "
            f"was regenerated without re-pinning the prose, or the prose cites a stale run.")


def test_no_percentage_in_the_benchmark_section_comes_from_anywhere_else(card):
    """The failure that actually happened: a figure from a different run, sitting in the one
    section whose credibility depends on the numbers being the committed ones."""
    allowed = set(_published(card).values()) | {"30%", "10%", "0%", "100%"}
    found = set(re.findall(r"\d+(?:\.\d+)?%", _benchmark_section(_read("README.md"))))
    stray = sorted(found - allowed)
    assert not stray, (
        f"the README's benchmark section quotes {stray}, which the committed scorecard does "
        f"not contain. Regenerate the scorecard and re-pin the prose, or delete the figure.")


def test_the_readme_states_the_scorecard_s_actual_verdict(card):
    """The legacy aggregate remains published while scoped statuses carry product meaning."""
    text = _read("README.md")
    verdict = card["verdict"]
    assert re.search(rf"headline.{{0,40}}reads\s+`{verdict}`", text, re.I | re.S), (
        f"the committed scorecard's aggregate verdict is {verdict!r}; the README should "
        "still state it plainly for backward compatibility.")
    for other in {"pass", "gap", "fail"} - {verdict}:
        assert f"headline verdict reads `{other}`" not in text, \
            f"the README claims the headline verdict is {other!r}; it is {verdict!r}"

    generator = card["status"]["generator_assurance"]
    benchmark = card["status"]["benchmark_validity"]
    assert f"generator-assurance status is `{generator['verdict']}`" in text
    assert re.search(
        rf"Benchmark-validity\s+status is `{benchmark['verdict']}`", text, re.I
    )
    assert re.search(r"Gate 4.{0,20}(red|fail)", text, re.I | re.S)


def test_public_evidenceforge_figures_are_bound_to_the_committed_measurement(ef_record):
    """Every duplicated EF count must be sourced from the provenance-bound JSON record."""
    results = ef_record["results"]
    sysmon = results["sysmon"]
    adapter = results["artifactforge_adapter_verification"]
    zeek = results["zeek_files"]
    forms = adapter["distinct_logical_identities_by_verified_seed_form"]
    expected = {
        "README.md": [
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


def test_the_design_doc_does_not_describe_a_red_gate_as_passing(card):
    """docs/DESIGN.md §4 documents the gate discipline; if a gate is red, it must say so."""
    failing = sorted(n for n, b in card["gates"].items() if b["verdict"] == "fail")
    design = _read("docs/DESIGN.md")
    for name in failing:
        assert re.search(rf"{name}.{{0,400}}(red|failing|currently fails)", design,
                         re.I | re.S), \
            f"gate '{name}' is failing but docs/DESIGN.md does not say so"
