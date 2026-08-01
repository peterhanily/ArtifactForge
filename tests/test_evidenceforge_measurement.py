# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Offline contract for the committed EvidenceForge measurement.

The full EvidenceForge run is intentionally not a default-test dependency.  The committed JSON
is the evidence record; these tests validate its provenance, arithmetic, audited figures, and
the renderer that lets prose source those figures without another ad-hoc measurement.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from artifactforge.ef_seeds import seed_from_host_metadata, seed_with_description

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "measure_evidenceforge.py"
RECORD = ROOT / "measurements" / "evidenceforge-v1.13.1-branch-office-example.json"

SPEC = importlib.util.spec_from_file_location("artifactforge_ef_measurement", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
measurement = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(measurement)


@pytest.fixture(scope="module")
def record():
    return json.loads(RECORD.read_text(encoding="utf-8"))


def test_record_is_canonical_valid_json_with_exact_upstream_provenance(record):
    measurement.validate_record(record)
    assert RECORD.read_text(encoding="utf-8") == json.dumps(
        record, indent=2, sort_keys=True
    ) + "\n"
    assert record["method"] == {
        "name": "artifactforge-evidenceforge-hash-surface",
        "network_required": False,
        "script": "scripts/measure_evidenceforge.py",
        "version": 2,
    }
    assert record["provenance"]["evidenceforge"] == measurement.PINNED_EVIDENCEFORGE
    assert record["provenance"]["scenario"] == measurement.PINNED_SCENARIO
    assert record["provenance"]["scenario_input_modified"] is False
    inventory = record["provenance"]["output_tree"]
    assert inventory["canonicalization"] == "artifactforge-output-tree-v1"
    assert inventory["file_count"] == len(inventory["files"]) == 45
    assert inventory["total_bytes"] == 32_635_868
    assert inventory["tree_sha256"] == (
        "956a9ae41bc94925412024cefaabb39a3c7c536a4441637ddc5cdfb09fad865d"
    )
    attestation = record["provenance"]["producer_attestation"]
    assert attestation["source"] == "required CLI arguments"
    assert attestation["automatically_detected_from_output"] is False
    assert attestation["bound_output_tree_sha256"] == inventory["tree_sha256"]
    assert "does not independently infer" in attestation["limitation"]


def test_full_unmodified_v1_13_1_counts_are_the_counts_of_record(record):
    results = record["results"]
    sysmon = results["sysmon"]
    assert sysmon["population_definition"] == (
        "Sysmon EID1/EID7 with non-empty image and SHA256"
    )
    assert sysmon["host_logs"] == 7
    assert sysmon["hashed_records"] == 853
    assert sysmon["distinct_hashes"] == {
        "md5": 105,
        "sha1": 105,
        "sha256": 105,
        "imphash": 105,
    }
    assert sysmon["event_id_1"] == {
        "hashed_records": 614,
        "distinct_hashes": {"md5": 78, "sha1": 78, "sha256": 78, "imphash": 78},
        "distinct_image_basenames": 57,
    }
    assert sysmon["event_id_7"] == {
        "hashed_records": 239,
        "distinct_hashes": {"md5": 27, "sha1": 27, "sha256": 27, "imphash": 27},
        "distinct_image_basenames": 20,
    }
    adapter = results["artifactforge_adapter_verification"]
    assert adapter == {
        "method": "artifactforge.ingest.evidenceforge.read_run",
        "evidenceforge_import_required": False,
        "records_with_sha256_and_image": 853,
        "records_recovered_and_verified": 853,
        "unrecovered_records": 0,
        "distinct_logical_identities": 105,
        "verified_records_by_seed_form": {
            "bare": 0,
            "from_host_metadata": 614,
            "with_description": 239,
        },
        "distinct_logical_identities_by_verified_seed_form": {
            "bare": 0,
            "from_host_metadata": 78,
            "with_description": 27,
        },
    }

    zeek = results["zeek_files"]
    assert (zeek["rows"], zeek["certificate_rows"], zeek["non_certificate_rows"]) == (
        722,
        525,
        197,
    )
    assert zeek["hashes"] == {
        "md5": {"rows": 547, "distinct": 125},
        "sha1": {"rows": 546, "distinct": 119},
        "sha256": {"rows": 525, "distinct": 103},
    }
    assert zeek["non_certificate_hashes"] == {
        "md5": {"rows": 22, "distinct": 22},
        "sha1": {"rows": 21, "distinct": 16},
        "sha256": {"rows": 0, "distinct": 0},
    }


def test_zero_intersections_keep_the_no_positive_same_file_qualification(record):
    intersections = record["results"]["intersections"]
    assert intersections["same_algorithm_all_sysmon_to_all_zeek"] == {
        "md5": 0,
        "sha1": 0,
        "sha256": 0,
    }
    assert intersections["same_algorithm_event_id_1_to_all_zeek"] == {
        "md5": 0,
        "sha1": 0,
        "sha256": 0,
    }
    assert intersections["same_algorithm_event_id_1_to_non_certificate_zeek"] == {
        "md5": 0,
        "sha1": 0,
        "sha256": 0,
    }
    assert intersections["any_digest_algorithm_all_sysmon_to_all_zeek"] == 0
    assert intersections[
        "event_id_1_image_to_non_certificate_filename_basenames"
    ] == {"count": 0, "values": []}
    assert intersections[
        "event_id_1_image_to_non_certificate_http_uri_basenames"
    ] == {"count": 0, "values": []}

    qualification = record["qualification"]
    assert qualification["positive_same_file_pair_demonstrated"] is False
    assert qualification["serialized_transfer_to_execution_identity_field"] is None
    assert "do not, by themselves" in qualification["claim_boundary"]
    assert "no positive transfer-to-execution same-file pair" in qualification["claim_boundary"]


def test_markdown_and_fact_api_source_values_from_the_record(record):
    facts = measurement.prose_facts(record)
    assert facts == {
        "sysmon_host_logs": 7,
        "sysmon_hashed_records": 853,
        "sysmon_distinct_sha256": 105,
        "sysmon_eid1_hashed_records": 614,
        "sysmon_eid1_distinct_sha1": 78,
        "adapter_records_recovered_and_verified": 853,
        "adapter_distinct_logical_identities": 105,
        "adapter_from_host_metadata_identities": 78,
        "adapter_with_description_identities": 27,
        "zeek_files_rows": 722,
        "zeek_certificate_rows": 525,
        "zeek_non_certificate_rows": 197,
        "zeek_distinct_sha1": 119,
        "zeek_distinct_sha256": 103,
        "sysmon_zeek_same_sha1_overlap": 0,
        "sysmon_zeek_same_sha256_overlap": 0,
    }
    markdown = measurement.render_markdown(record)
    assert "| Sysmon hashed records | 853 |" in markdown
    assert "| Adapter records recovered and verified | 853 / 853 |" in markdown
    assert "| Verified identities: host-metadata / with-description | 78 / 27 |" in markdown
    assert "| Zeek certificate / non-certificate rows | 525 / 197 |" in markdown
    assert record["qualification"]["claim_boundary"] in markdown

    changed = copy.deepcopy(record)
    changed["results"]["sysmon"]["distinct_hashes"]["sha256"] = 4242
    assert "| Distinct Sysmon SHA256 | 4242 |" in measurement.render_markdown(changed)


def test_check_and_render_cli_are_offline(record):
    checked = subprocess.run(
        [sys.executable, str(SCRIPT), "check", str(RECORD)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert checked.stdout == f"OK: {RECORD}\n"
    rendered = subprocess.run(
        [sys.executable, str(SCRIPT), "render", str(RECORD)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "| Sysmon EID1 hashed records | 614 |" in rendered.stdout
    assert record["provenance"]["scenario"]["sha256"] in rendered.stdout


def test_serialized_parser_has_positive_controls_without_evidenceforge(tmp_path):
    """A tiny tree makes sure zeroes cannot arise from a parser that found nothing."""

    host = tmp_path / "data" / "WS-01.example"
    host.mkdir(parents=True)
    shared_sha1 = "A" * 40
    sysmon_sha256 = "B" * 64
    sysmon_event = (
        "<Event><System><EventID>1</EventID></System><EventData>"
        '<Data Name="Image">C:\\Temp\\update.exe</Data>'
        f'<Data Name="Hashes">SHA1={shared_sha1},SHA256={sysmon_sha256}</Data>'
        "</EventData></Event>"
    )
    (host / "windows_event_sysmon.xml").write_text(
        f"<Events>{sysmon_event}</Events>", encoding="utf-8"
    )

    zeek = tmp_path / "data" / "ZEEK-01"
    zeek.mkdir()
    files_row = {
        "fuid": "F1",
        "conn_uids": ["C1"],
        "source": "HTTP",
        "filename": "update.exe",
        "mime_type": "application/x-dosexec",
        "sha1": shared_sha1.lower(),
    }
    (zeek / "files.json").write_text(json.dumps(files_row) + "\n", encoding="utf-8")
    (zeek / "http.json").write_text(
        json.dumps({"uid": "C1", "uri": "/update.exe"}) + "\n", encoding="utf-8"
    )

    results = measurement.analyze_output(tmp_path)
    assert results["sysmon"]["hashed_records"] == 1
    assert results["zeek_files"]["rows"] == 1
    assert results["intersections"]["same_algorithm_event_id_1_to_all_zeek"]["sha1"] == 1
    assert results["intersections"][
        "event_id_1_image_to_non_certificate_filename_basenames"
    ]["values"] == ["update.exe"]
    assert results["intersections"][
        "event_id_1_image_to_non_certificate_http_uri_basenames"
    ]["values"] == ["update.exe"]


def test_seed_forms_are_verified_from_hashes_not_inferred_from_event_id(tmp_path):
    """Cross the usual call shapes: EID1 uses description; EID7 uses host metadata.

    The deliberately invalid fourth record is the negative control: it has an EventID but must
    not be assigned a form because no candidate seed reproduces its emitted SHA256.
    """

    file_version = "1.2.3.4"
    description = "Fixture binary"
    product = "Fixture product"
    company = "Fixture company"
    original_name = "fixture.exe"

    def digest(seed):
        return hashlib.sha256(seed.encode()).hexdigest().upper()

    def event(event_id, image, sha256):
        image_field = "ImageLoaded" if event_id == 7 else "Image"
        fields = {
            image_field: image,
            "FileVersion": file_version,
            "Description": description,
            "Product": product,
            "Company": company,
            "OriginalFileName": original_name,
            "Hashes": f"SHA256={sha256}",
        }
        data = "".join(f'<Data Name="{key}">{value}</Data>' for key, value in fields.items())
        return (
            f"<Event><System><EventID>{event_id}</EventID></System>"
            f"<EventData>{data}</EventData></Event>"
        )

    eid1_images = [r"C:\Temp\one.exe", r"C:\Temp\two.exe"]
    events = [
        event(
            1,
            image,
            digest(
                seed_with_description(
                    image,
                    file_version,
                    description,
                    product,
                    company,
                    original_name,
                )
            ),
        )
        for image in eid1_images
    ]
    eid7_image = r"C:\Windows\System32\fixture.dll"
    events.append(
        event(
            7,
            eid7_image,
            digest(
                seed_from_host_metadata(
                    eid7_image, file_version, product, company, original_name
                )
            ),
        )
    )
    events.append(event(1, r"C:\Temp\invalid.exe", "F" * 64))

    host = tmp_path / "data" / "WS-CROSSED.example"
    host.mkdir(parents=True)
    (host / "windows_event_sysmon.xml").write_text(
        "<Events>" + "".join(events) + "</Events>", encoding="utf-8"
    )

    results = measurement.analyze_output(tmp_path)
    assert results["sysmon"]["event_id_1"]["hashed_records"] == 3
    assert results["sysmon"]["event_id_7"]["hashed_records"] == 1
    adapter = results["artifactforge_adapter_verification"]
    assert adapter["records_with_sha256_and_image"] == 4
    assert adapter["records_recovered_and_verified"] == 3
    assert adapter["unrecovered_records"] == 1
    assert adapter["verified_records_by_seed_form"] == {
        "bare": 0,
        "from_host_metadata": 1,
        "with_description": 2,
    }
    assert adapter["distinct_logical_identities_by_verified_seed_form"] == {
        "bare": 0,
        "from_host_metadata": 1,
        "with_description": 2,
    }
    # Event-type inference would report 3/1 here, including the unverified record.
    assert adapter["verified_records_by_seed_form"] != {
        "bare": 0,
        "from_host_metadata": 3,
        "with_description": 1,
    }


def test_schema_rejects_broken_arithmetic_and_lost_qualification(record):
    broken = copy.deepcopy(record)
    broken["results"]["sysmon"]["hashed_records"] += 1
    with pytest.raises(ValueError, match="do not add up"):
        measurement.validate_record(broken)

    broken = copy.deepcopy(record)
    broken["qualification"]["positive_same_file_pair_demonstrated"] = True
    with pytest.raises(ValueError, match="no-positive-pair"):
        measurement.validate_record(broken)

    broken = copy.deepcopy(record)
    broken["provenance"]["output_tree"]["files"][0]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="tree SHA256"):
        measurement.validate_record(broken)


def test_wrong_or_retained_producer_metadata_cannot_stamp_a_pinned_record(tmp_path, record):
    with pytest.raises(ValueError, match="producer attestation"):
        measurement._validated_pinned_producer("1.12.0", measurement.PINNED_EVIDENCEFORGE[
            "git_commit"
        ])
    with pytest.raises(ValueError, match="producer attestation"):
        measurement._validated_pinned_producer("1.13.1", "0" * 40)

    retained = copy.deepcopy(record)
    retained["provenance"]["evidenceforge"]["git_commit"] = "0" * 40
    with pytest.raises(ValueError, match="pinned EvidenceForge release"):
        measurement.validate_record(retained)

    # A pre-existing output record must remain untouched when the newly supplied producer
    # attestation is wrong; validation happens before the scenario or output tree is read.
    output = tmp_path / "retained-record.json"
    original = '{"stale": "pinned-looking metadata"}\n'
    output.write_text(original, encoding="utf-8")
    failed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "measure",
            str(tmp_path / "arbitrary-output"),
            "--scenario",
            str(tmp_path / "arbitrary-scenario.yaml"),
            "--evidenceforge-version",
            "1.12.0",
            "--evidenceforge-commit",
            measurement.PINNED_EVIDENCEFORGE["git_commit"],
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
    )
    assert failed.returncode != 0
    assert "producer attestation does not match" in failed.stderr
    assert output.read_text(encoding="utf-8") == original


def test_output_binding_detects_tampering(tmp_path, record):
    image = r"C:\Windows\System32\verified.exe"
    file_version = "1.0.0.0"
    product = "Fixture"
    company = "Fixture"
    original_name = "verified.exe"
    seed = seed_from_host_metadata(image, file_version, product, company, original_name)
    sha256 = hashlib.sha256(seed.encode()).hexdigest().upper()
    fields = {
        "Image": image,
        "FileVersion": file_version,
        "Description": "Verified fixture",
        "Product": product,
        "Company": company,
        "OriginalFileName": original_name,
        "Hashes": f"SHA256={sha256}",
    }
    data = "".join(f'<Data Name="{key}">{value}</Data>' for key, value in fields.items())
    event = (
        "<Event><System><EventID>1</EventID></System>"
        f"<EventData>{data}</EventData></Event>"
    )
    host = tmp_path / "data" / "WS-BOUND.example"
    host.mkdir(parents=True)
    sysmon_path = host / "windows_event_sysmon.xml"
    sysmon_path.write_text(f"<Events>{event}</Events>", encoding="utf-8")

    bound = copy.deepcopy(record)
    inventory = measurement.output_tree_inventory(tmp_path)
    bound["provenance"]["output_tree"] = inventory
    bound["provenance"]["producer_attestation"][
        "bound_output_tree_sha256"
    ] = inventory["tree_sha256"]
    bound["results"] = measurement.analyze_output(tmp_path)
    measurement.validate_record(bound)
    measurement.verify_output_binding(bound, tmp_path)

    sysmon_path.write_text(sysmon_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="output tree does not match"):
        measurement.verify_output_binding(bound, tmp_path)


def test_raw_sysmon_population_requires_sha256_and_image(tmp_path):
    image = r"C:\Windows\System32\counted.exe"
    file_version = "2.0.0.0"
    product = "Fixture"
    company = "Fixture"
    original_name = "counted.exe"
    seed = seed_from_host_metadata(image, file_version, product, company, original_name)
    valid_sha256 = hashlib.sha256(seed.encode()).hexdigest().upper()

    def event(hashes, *, include_image=True):
        fields = {
            "FileVersion": file_version,
            "Description": "Population fixture",
            "Product": product,
            "Company": company,
            "OriginalFileName": original_name,
            "Hashes": hashes,
        }
        if include_image:
            fields["Image"] = image
        data = "".join(f'<Data Name="{key}">{value}</Data>' for key, value in fields.items())
        return (
            "<Event><System><EventID>1</EventID></System>"
            f"<EventData>{data}</EventData></Event>"
        )

    events = [
        event(f"SHA256={valid_sha256}"),
        event("SHA1=" + "A" * 40),
        event("SHA256=" + "B" * 64, include_image=False),
    ]
    host = tmp_path / "data" / "WS-POPULATION.example"
    host.mkdir(parents=True)
    (host / "windows_event_sysmon.xml").write_text(
        "<Events>" + "".join(events) + "</Events>", encoding="utf-8"
    )

    results = measurement.analyze_output(tmp_path)
    assert results["sysmon"]["hashed_records"] == 1
    assert results["artifactforge_adapter_verification"][
        "records_with_sha256_and_image"
    ] == 1
