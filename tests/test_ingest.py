# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The companion adapter, exercised without EvidenceForge installed.

That is the point of it. The adapter reads an output tree, so it is testable against a tree
we write ourselves — which means the companion path has coverage in the default suite rather
than only in the job that installs upstream.

The hostile cases matter more than the happy one here. A malformed `Hashes` field used to
abort an entire ingest over a real run, because the parse was
`dict(kv.split("=") for kv in field.split(","))` with nothing catching a field that had no
`=` in it. One unreadable record in sixty thousand should be a skipped record, not a crash.
"""
import hashlib
import os

import pytest

from artifactforge.ef_seeds import seed_from_host_metadata, seed_with_description
from artifactforge.ingest.evidenceforge import _EF_LAYOUT, _parse_hashes, read_run

IMAGE = r"C:\Windows\System32\svchost.exe"
META = ("10.0.19041.1", "Host Process", "Microsoft Windows", "Microsoft Corporation",
        "svchost.exe")


def _digest(seed):
    return hashlib.sha256(seed.encode()).hexdigest().upper()


def _event(event_id, image, hashes, *, description=None):
    fv, desc, prod, comp, orig = META
    fields = {
        "Image" if event_id == 1 else "ImageLoaded": image,
        "FileVersion": fv, "Product": prod, "Company": comp, "OriginalFileName": orig,
        "Hashes": hashes,
    }
    if description is not None:
        fields["Description"] = description
    data = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in fields.items())
    return f"<Event><System><EventID>{event_id}</EventID></System><EventData>{data}</EventData></Event>"


def _run_dir(tmp_path, events, host="WS-01.example.local"):
    d = tmp_path / _EF_LAYOUT["hosts_dir"] / host
    d.mkdir(parents=True)
    (d / _EF_LAYOUT["sysmon_log"]).write_text("<Events>" + "".join(events) + "</Events>")
    return str(tmp_path)


def test_reads_both_seed_forms_from_an_output_tree(tmp_path):
    fv, desc, prod, comp, orig = META
    host_form = _digest(seed_from_host_metadata(IMAGE, fv, prod, comp, orig))
    desc_form = _digest(seed_with_description(IMAGE, fv, desc, prod, comp, orig))
    run = read_run(_run_dir(tmp_path, [
        _event(1, IMAGE, f"SHA1=AA,MD5=BB,SHA256={host_form}"),
        _event(7, IMAGE, f"SHA256={desc_form},IMPHASH=CC", description=desc),
    ]))
    assert run.records_with_hashes == 2
    assert run.records_recovered == 2
    assert run.recovery_rate == 1.0
    assert {b.seed_form for b in run.binaries.values()} == {"from_host_metadata",
                                                            "with_description"}


def test_one_binary_seen_on_several_hosts_is_one_identity(tmp_path):
    fv, _desc, prod, comp, orig = META
    digest = _digest(seed_from_host_metadata(IMAGE, fv, prod, comp, orig))
    root = tmp_path
    for host in ("WS-01.example.local", "WS-02.example.local"):
        d = root / _EF_LAYOUT["hosts_dir"] / host
        d.mkdir(parents=True)
        (d / _EF_LAYOUT["sysmon_log"]).write_text(
            "<Events>" + _event(1, IMAGE, f"SHA256={digest}") * 3 + "</Events>")
    run = read_run(str(root))
    assert len(run.binaries) == 1
    binary = next(iter(run.binaries.values()))
    assert binary.records == 6
    assert len(binary.hosts) == 2


@pytest.mark.parametrize("field", [
    "brokenfield", "", "MD5=AA", "SHA256", "SHA256=,MD5=AA", "=,=,=", "SHA1=AA,MD5",
])
def test_a_malformed_hash_field_skips_the_record_instead_of_aborting_the_run(tmp_path, field):
    fv, _desc, prod, comp, orig = META
    good = _digest(seed_from_host_metadata(IMAGE, fv, prod, comp, orig))
    run = read_run(_run_dir(tmp_path, [
        _event(1, IMAGE, field),
        _event(1, IMAGE, f"SHA256={good}"),
    ]))
    assert run.records_recovered == 1, "the readable record must still be ingested"


def test_a_digest_matching_no_seed_form_is_reported_not_raised(tmp_path):
    """Upstream drift has to be visible without taking the whole ingest down with it."""
    run = read_run(_run_dir(tmp_path, [_event(1, IMAGE, "SHA256=" + "F" * 64)]))
    assert run.records_with_hashes == 1
    assert run.records_recovered == 0
    assert run.unrecovered and "seed forms reproduce" in run.unrecovered[0][1]


def test_parse_hashes_is_total():
    assert _parse_hashes("SHA256=AA,MD5=BB") == {"SHA256": "AA", "MD5": "BB"}
    assert _parse_hashes("junk") == {}
    assert _parse_hashes("") == {}
    assert _parse_hashes(None) == {}
    assert _parse_hashes("a=b=c") == {"A": "b=c"}


def test_a_directory_that_is_not_a_run_says_so(tmp_path):
    with pytest.raises(FileNotFoundError, match="does not look like an EvidenceForge run"):
        read_run(str(tmp_path))


def test_hosts_without_sysmon_are_simply_absent(tmp_path):
    (tmp_path / _EF_LAYOUT["hosts_dir"] / "FW-EDGE").mkdir(parents=True)
    (tmp_path / _EF_LAYOUT["hosts_dir"] / "FW-EDGE" / "cisco_asa.log").write_text("x")
    run = read_run(str(tmp_path))
    assert run.hosts == []
    assert run.recovery_rate == 0.0
    assert os.path.isdir(os.path.join(str(tmp_path), _EF_LAYOUT["hosts_dir"]))
