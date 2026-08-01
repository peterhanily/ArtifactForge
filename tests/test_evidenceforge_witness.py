# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Offline and mutation tests for the controlled EvidenceForge hash witness."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "measure_evidenceforge_witness.py"
SCENARIO = (
    ROOT / "integration" / "evidenceforge" / "scenarios" / "content-identity-witness-v1.13.1.yaml"
)
RECORD = ROOT / "measurements" / "evidenceforge-v1.13.1-controlled-content-identity.json"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

SPEC = importlib.util.spec_from_file_location("artifactforge_ef_witness", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
witness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(witness)

DOWNLOAD_IMAGE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CONTROL_PATH = witness.CONTROL_PATH
NEGATIVE_PATH = r"C:\Windows\Temp\af-controlled.exe"
PROCESS_ONLY_PATH = r"C:\Windows\System32\whoami.exe"
CONTROL_GUID = "{11111111-1111-1111-1111-111111111111}"
TARGET_GUID = "{22222222-2222-2222-2222-222222222222}"
NEGATIVE_GUID = "{33333333-3333-3333-3333-333333333333}"


def _write_json_lines(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _event_xml(
    event_id: int,
    timestamp: str,
    fields: dict[str, object],
) -> str:
    escaped = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
    }

    def xml(value: object) -> str:
        result = str(value)
        for original, replacement in escaped.items():
            result = result.replace(original, replacement)
        return result

    data = "".join(
        f'<Data Name="{xml(name)}">{xml(value)}</Data>' for name, value in fields.items()
    )
    return (
        "<Event><System>"
        f"<EventID>{event_id}</EventID>"
        f'<TimeCreated SystemTime="{timestamp}"/>'
        "</System><EventData>"
        f"{data}</EventData></Event>"
    )


def _process_fields(
    image: str,
    pid: int,
    guid: str,
    user: str,
    *,
    hashes: str = "SHA1=" + "a" * 40 + ",SHA256=" + "b" * 64,
) -> dict[str, object]:
    return {
        "Image": image,
        "ProcessId": pid,
        "ProcessGuid": guid,
        "User": user,
        "Hashes": hashes,
        "FileVersion": "-",
        "Product": "-",
        "Company": "-",
        "OriginalFileName": "-",
    }


def _make_run(root: Path) -> Path:
    data = root / "data"
    host = data / "WS-AF-01.artifactforge.test"
    zeek = data / "ZEEK-AF-01"
    host.mkdir(parents=True)
    zeek.mkdir(parents=True)

    events = [
        {
            "record_id": "controlled-download-execute#0",
            "kind": "process",
            "storyline_id": "controlled-download-execute",
            "time": "2024-05-14T12:20:15Z",
            "actor": "SYSTEM",
            "system": "WS-AF-01",
            "activity": "controlled",
            "emitted": True,
            "attributes": {
                "network_url": witness.CONTROL_URL,
                "output_file": CONTROL_PATH,
                "process_name": DOWNLOAD_IMAGE,
                "pid": 6632,
            },
        },
        {
            "record_id": "controlled-download-execute#1",
            "kind": "process",
            "storyline_id": "controlled-download-execute",
            "time": "2024-05-14T12:20:45Z",
            "actor": "SYSTEM",
            "system": "WS-AF-01",
            "activity": "controlled",
            "emitted": True,
            "attributes": {"process_name": CONTROL_PATH, "pid": 6648},
        },
        {
            "record_id": "unrelated-download#0",
            "kind": "process",
            "storyline_id": "unrelated-download",
            "time": "2024-05-14T12:34:43Z",
            "actor": "casey.analyst",
            "system": "WS-AF-01",
            "activity": "negative transfer",
            "emitted": True,
            "attributes": {
                "network_url": "http://203.0.113.20/af-controlled.exe",
                "output_file": NEGATIVE_PATH,
                "process_name": DOWNLOAD_IMAGE,
                "pid": 6692,
            },
        },
        {
            "record_id": "unrelated-execution#0",
            "kind": "process",
            "storyline_id": "unrelated-execution",
            "time": "2024-05-14T12:50:23Z",
            "actor": "casey.analyst",
            "system": "WS-AF-01",
            "activity": "negative execution",
            "emitted": True,
            "attributes": {"process_name": PROCESS_ONLY_PATH, "pid": 6732},
        },
    ]
    (root / "GROUND_TRUTH.json").write_text(json.dumps({"events": events}), encoding="utf-8")

    mime = "application/x-msdownload"
    positive_length = 123
    negative_length = 456
    positive_seed = f"http:203.0.113.10:/af-controlled.exe:{positive_length}:{mime}"
    negative_seed = f"http:203.0.113.20:/af-controlled.exe:{negative_length}:{mime}"
    _write_json_lines(
        zeek / "http.json",
        [
            {
                "ts": 1715689217.377389,
                "uid": "C-POSITIVE",
                "id.orig_h": "192.0.2.10",
                "id.resp_h": "203.0.113.10",
                "host": "203.0.113.10",
                "uri": "/af-controlled.exe",
                "method": "GET",
                "status_code": 200,
                "response_body_len": positive_length,
                "resp_fuids": ["F-POSITIVE"],
            },
            {
                "ts": 1715690085.195726,
                "uid": "C-NEGATIVE",
                "id.orig_h": "192.0.2.10",
                "id.resp_h": "203.0.113.20",
                "host": "203.0.113.20",
                "uri": "/af-controlled.exe",
                "method": "GET",
                "status_code": 200,
                "response_body_len": negative_length,
                "resp_fuids": ["F-NEGATIVE"],
            },
        ],
    )
    _write_json_lines(
        zeek / "files.json",
        [
            {
                "ts": 1715689217.485389,
                "fuid": "F-POSITIVE",
                "conn_uids": ["C-POSITIVE"],
                "tx_hosts": ["203.0.113.10"],
                "rx_hosts": ["192.0.2.10"],
                "source": "HTTP",
                "analyzers": ["SHA1"],
                "mime_type": mime,
                "seen_bytes": positive_length,
                "total_bytes": positive_length,
                "missing_bytes": 0,
                "overflow_bytes": 0,
                "timedout": False,
                "sha1": hashlib.sha1(positive_seed.encode()).hexdigest(),
            },
            {
                "ts": 1715690085.327726,
                "fuid": "F-NEGATIVE",
                "conn_uids": ["C-NEGATIVE"],
                "tx_hosts": ["203.0.113.20"],
                "rx_hosts": ["192.0.2.10"],
                "source": "HTTP",
                "analyzers": ["SHA1"],
                "mime_type": mime,
                "seen_bytes": negative_length,
                "total_bytes": negative_length,
                "missing_bytes": 0,
                "overflow_bytes": 0,
                "timedout": False,
                "sha1": hashlib.sha1(negative_seed.encode()).hexdigest(),
            },
        ],
    )

    sysmon_seed = f"{CONTROL_PATH.lower()}:-:-:-:-"
    target_hashes = (
        f"SHA1={hashlib.sha1(sysmon_seed.encode()).hexdigest()},"
        f"SHA256={hashlib.sha256(sysmon_seed.encode()).hexdigest()}"
    )
    sysmon_events = [
        _event_xml(
            1,
            "2024-05-14T12:20:16.3606449Z",
            _process_fields(DOWNLOAD_IMAGE, 6632, CONTROL_GUID, r"NT AUTHORITY\SYSTEM"),
        ),
        _event_xml(
            11,
            "2024-05-14T12:20:18.2730050Z",
            {
                "Image": DOWNLOAD_IMAGE,
                "ProcessId": 6632,
                "ProcessGuid": CONTROL_GUID,
                "TargetFilename": CONTROL_PATH,
                "User": r"NT AUTHORITY\SYSTEM",
            },
        ),
        _event_xml(
            1,
            "2024-05-14T12:20:45.8769464Z",
            _process_fields(
                CONTROL_PATH,
                6648,
                TARGET_GUID,
                r"NT AUTHORITY\SYSTEM",
                hashes=target_hashes,
            ),
        ),
        _event_xml(
            1,
            "2024-05-14T12:34:43.9362310Z",
            _process_fields(DOWNLOAD_IMAGE, 6692, NEGATIVE_GUID, r"ARTIFACTFORGE\casey.analyst"),
        ),
        _event_xml(
            11,
            "2024-05-14T12:34:45.2464475Z",
            {
                "Image": DOWNLOAD_IMAGE,
                "ProcessId": 6692,
                "ProcessGuid": NEGATIVE_GUID,
                "TargetFilename": NEGATIVE_PATH,
                "User": r"ARTIFACTFORGE\casey.analyst",
            },
        ),
        _event_xml(
            1,
            "2024-05-14T12:50:23.2379331Z",
            _process_fields(
                PROCESS_ONLY_PATH,
                6732,
                "{44444444-4444-4444-4444-444444444444}",
                r"ARTIFACTFORGE\casey.analyst",
            ),
        ),
    ]
    (host / "windows_event_sysmon.xml").write_text(
        "<Events>" + "".join(sysmon_events) + "</Events>", encoding="utf-8"
    )
    return root


@pytest.fixture
def run_root(tmp_path: Path) -> Path:
    return _make_run(tmp_path / "run")


@pytest.fixture(scope="module")
def record() -> dict[str, object]:
    return json.loads(RECORD.read_text(encoding="utf-8"))


def test_committed_record_is_canonical_and_pinned(record: dict[str, object]) -> None:
    witness.validate_record(record)
    assert RECORD.read_text(encoding="utf-8") == json.dumps(record, indent=2, sort_keys=True) + "\n"
    assert record["provenance"]["evidenceforge"] == witness.PINNED_EVIDENCEFORGE
    assert record["provenance"]["scenario"] == witness.PINNED_SCENARIO
    assert record["provenance"]["generation_runtime"] == witness.PINNED_RUNTIME
    inventory = record["provenance"]["output_tree"]
    assert inventory["file_count"] == len(inventory["files"]) == 17
    assert inventory["total_bytes"] == 756_280
    assert inventory["tree_sha256"] == (
        "6754e59cb6bcb2af9afbb94b93e6c1378568d539d69f45aa9e38ce37414f58b8"
    )
    assert record["witness"]["cross_emitter_join"] == {
        "algorithm": "sha1",
        "zeek_sha1": "35a96017abff36254a0d4a6399c9fbe0cbd8b6a2",
        "sysmon_sha1": "025ee09748833e745cd43c1d333d6910958f3919",
        "equal": False,
    }
    assert record["witness"]["pair_selection"]["digest_blind"] is True


def test_controlled_parser_accepts_complete_synthetic_chain(run_root: Path) -> None:
    result = witness.analyze_output(run_root)
    assert result["timeline"]["ordered"] is True
    assert result["sysmon_process"]["downloader_process_guid"] == CONTROL_GUID
    assert result["sysmon_process"]["file_create_process_guid"] == CONTROL_GUID
    assert result["negative_controls"]["same_basename_different_path"] is True


def test_digest_replacement_cannot_change_pair_selection(run_root: Path) -> None:
    relation = witness._ground_truth_relation(run_root)
    zeek_before = witness._select_http_file_rows(run_root, witness.CONTROL_URL)
    sysmon_before = witness._select_sysmon_chain(run_root, relation)

    files_path = run_root / "data" / "ZEEK-AF-01" / "files.json"
    files_path.write_text(
        files_path.read_text(encoding="utf-8").replace(zeek_before["file"]["sha1"], "f" * 40, 1),
        encoding="utf-8",
    )
    sysmon_path = run_root / "data" / "WS-AF-01.artifactforge.test" / "windows_event_sysmon.xml"
    original_hashes = sysmon_before["target"]["fields"]["Hashes"]
    sysmon_path.write_text(
        sysmon_path.read_text(encoding="utf-8").replace(
            original_hashes, "SHA1=" + "e" * 40 + ",SHA256=" + "d" * 64, 1
        ),
        encoding="utf-8",
    )

    zeek_after = witness._select_http_file_rows(run_root, witness.CONTROL_URL)
    sysmon_after = witness._select_sysmon_chain(run_root, relation)
    assert (zeek_before["http"]["uid"], zeek_before["file"]["fuid"]) == (
        zeek_after["http"]["uid"],
        zeek_after["file"]["fuid"],
    )
    assert (
        sysmon_before["downloader"]["time"],
        sysmon_before["file_create"]["time"],
        sysmon_before["target"]["time"],
    ) == (
        sysmon_after["downloader"]["time"],
        sysmon_after["file_create"]["time"],
        sysmon_after["target"]["time"],
    )


@pytest.mark.parametrize(
    ("relative_path", "old", "new"),
    [
        (
            "GROUND_TRUTH.json",
            '"storyline_id": "controlled-download-execute"',
            '"storyline_id": "mutated-storyline"',
        ),
        ("data/ZEEK-AF-01/files.json", '"conn_uids": ["C-POSITIVE"]', '"conn_uids": ["C-MUTATED"]'),
        (
            "data/ZEEK-AF-01/http.json",
            '"id.orig_h": "192.0.2.10"',
            '"id.orig_h": "192.0.2.99"',
        ),
        (
            "data/ZEEK-AF-01/http.json",
            '"resp_fuids": ["F-POSITIVE"]',
            '"resp_fuids": ["F-MUTATED"]',
        ),
        (
            "data/WS-AF-01.artifactforge.test/windows_event_sysmon.xml",
            f'<Data Name="TargetFilename">{CONTROL_PATH}</Data>',
            '<Data Name="TargetFilename">C:\\Windows\\System32\\mutated.exe</Data>',
        ),
        (
            "data/WS-AF-01.artifactforge.test/windows_event_sysmon.xml",
            '<Data Name="ProcessId">6648</Data>',
            '<Data Name="ProcessId">9999</Data>',
        ),
        (
            "data/WS-AF-01.artifactforge.test/windows_event_sysmon.xml",
            CONTROL_GUID,
            "{99999999-9999-9999-9999-999999999999}",
        ),
        ("data/ZEEK-AF-01/files.json", '"sha1": "', '"no_sha1": "'),
    ],
)
def test_identity_and_completeness_mutations_fail(
    run_root: Path,
    relative_path: str,
    old: str,
    new: str,
) -> None:
    path = run_root / relative_path
    source = path.read_text(encoding="utf-8")
    assert old in source
    path.write_text(source.replace(old, new, 1), encoding="utf-8")
    with pytest.raises(ValueError):
        witness.analyze_output(run_root)


def test_same_basename_decoy_is_required(run_root: Path) -> None:
    path = run_root / "GROUND_TRUTH.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    negative = next(
        item for item in document["events"] if item["record_id"] == "unrelated-download#0"
    )
    negative["attributes"]["output_file"] = r"C:\Windows\Temp\different.exe"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="same-basename"):
        witness.analyze_output(run_root)


def test_build_record_rejects_wrong_source_and_scenario_pins(
    run_root: Path, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="producer attestation"):
        witness.build_record(
            run_root,
            SCENARIO,
            evidenceforge_version="1.13.1",
            evidenceforge_commit="0" * 40,
            python_version="3.12.13",
        )
    changed_scenario = tmp_path / "changed.yaml"
    shutil.copyfile(SCENARIO, changed_scenario)
    changed_scenario.write_text(
        changed_scenario.read_text(encoding="utf-8").replace(
            "name: content-identity-witness-v1-13-1", "name: changed"
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="exact committed controlled fixture"):
        witness.build_record(
            run_root,
            changed_scenario,
            evidenceforge_version="1.13.1",
            evidenceforge_commit=witness.PINNED_EVIDENCEFORGE["git_commit"],
            python_version="3.12.13",
        )

    with pytest.raises(ValueError, match="producer Python"):
        witness.build_record(
            run_root,
            SCENARIO,
            evidenceforge_version="1.13.1",
            evidenceforge_commit=witness.PINNED_EVIDENCEFORGE["git_commit"],
            python_version="3.12.12",
        )


def test_output_tree_binding_rejects_a_later_change(run_root: Path) -> None:
    record = witness.build_record(
        run_root,
        SCENARIO,
        evidenceforge_version="1.13.1",
        evidenceforge_commit=witness.PINNED_EVIDENCEFORGE["git_commit"],
        python_version="3.12.13",
    )
    (run_root / "late-file.txt").write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="output tree"):
        witness.verify_output_binding(record, run_root)


def test_offline_check_and_render_cli(record: dict[str, object]) -> None:
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
    assert "Same logical-file SHA1 join | **FAIL**" in rendered.stdout
    assert record["qualification"]["claim_boundary"] in rendered.stdout


def test_pinned_ci_regenerates_and_rebinds_the_controlled_witness() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    contract = workflow.split("  ef-contract:\n", 1)[1].split("  ef-drift-canary:\n", 1)[0]
    for required in (
        "uv python install 3.12.13",
        "--constraint integration/evidenceforge/constraints-v1.13.1.txt",
        "content-identity-witness-v1.13.1.yaml",
        "scripts/measure_evidenceforge_witness.py",
        "evidenceforge-v1.13.1-controlled-content-identity.json",
        "--run-root ef-witness-out",
    ):
        assert required in contract
    assert "continue-on-error" not in contract


def test_serialized_validation_rejects_claim_inflation(record: dict[str, object]) -> None:
    changed = copy.deepcopy(record)
    changed["qualification"]["shared_materialized_bytes_demonstrated"] = True
    with pytest.raises(ValueError, match="materialized bytes"):
        witness.validate_record(changed)


def test_serialized_validation_recomputes_cached_evidence(record: dict[str, object]) -> None:
    changed = copy.deepcopy(record)
    changed["witness"]["timeline"]["epoch_seconds"]["sysmon_target_eid1"] += 1
    with pytest.raises(ValueError, match="derived from"):
        witness.validate_record(changed)

    changed = copy.deepcopy(record)
    changed["witness"]["negative_controls"]["zeek_file"]["seed_material"] += "-edited"
    with pytest.raises(ValueError, match="negative controls"):
        witness.validate_record(changed)

    changed = copy.deepcopy(record)
    changed["method"]["version"] += 1
    with pytest.raises(ValueError, match="method declaration"):
        witness.validate_record(changed)
