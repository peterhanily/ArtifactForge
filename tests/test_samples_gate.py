# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The committed samples are re-read by the real parsers on every run.

A gallery is the most likely thing in a repository to rot: it is generated once, committed,
and then never looked at again while the code underneath it moves. These tests point the same
oracles at the committed bytes that the gates point at freshly generated ones, so a sample
that stops being valid fails here rather than in someone's hands.

They also check the two properties that make committing binaries defensible at all — every
one is inert, and every one discloses itself.
"""

import glob
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil

import pytest

from artifactforge.gates import identity, inertness, validity
from artifactforge.inventory import inventory_regular_files

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = sorted(glob.glob(os.path.join(ROOT, "samples", "*", "")))
SAMPLE_WRITER_PATH = Path(ROOT) / "scripts" / "write_sample_docs.py"

pytestmark = pytest.mark.skipif(not SAMPLES, reason="no samples committed")


def _load_sample_writer():
    spec = importlib.util.spec_from_file_location("artifactforge_sample_writer", SAMPLE_WRITER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _ids(paths):
    return [os.path.basename(p.rstrip(os.sep)) for p in paths]


def _ground_truth(sample):
    with open(os.path.join(sample, "ARTIFACT_ANSWERS.json")) as f:
        return json.load(f)


@pytest.mark.parametrize("sample", SAMPLES, ids=_ids)
def test_every_committed_artifact_still_parses(sample):
    pytest.importorskip("pefile")
    report = validity.run(sample)
    assert report.ok, report.render()


@pytest.mark.parametrize("sample", SAMPLES, ids=_ids)
def test_every_committed_sample_is_inert_and_marked(sample):
    report = inertness.run(sample)
    assert report.ok, report.render()


@pytest.mark.parametrize("sample", SAMPLES, ids=_ids)
def test_the_committed_answer_key_still_matches_the_committed_bytes(sample, tmp_path):
    """Public evidence claims are re-derived from committed files, not private evaluator state."""
    pytest.importorskip("regipy")
    truth = _ground_truth(sample)
    join = truth["derived_evidence"]
    identity_scene = sample
    if join.get("family") == "linux":
        # Gate 2's Linux scene contract is an exact artifact-only inventory.  Keep the
        # gallery README and public answer metadata outside the tree being measured.
        declared = [
            *(record["served_relpath"] for record in join["residents"]),
            *(record["served_relpath"] for record in join["autostart"]),
            join["bash_history"]["served_relpath"],
        ]
        source_root = Path(sample)
        for relative_path in declared:
            source = source_root / relative_path
            destination = tmp_path / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        identity_scene = os.fspath(tmp_path)
    report = identity.run(identity_scene, join)
    assert report.ok, report.render()
    assert report.metrics["checks_joined"] == report.metrics["checks_total"]


@pytest.mark.parametrize("sample", SAMPLES, ids=_ids)
def test_the_answer_key_says_it_is_synthetic(sample):
    truth = _ground_truth(sample)
    assert truth["synthetic"] is True
    assert "not evidence" in truth["notice"].lower()
    assert truth["answers"], "a sample with no answers is not a sample"


@pytest.mark.parametrize("sample", SAMPLES, ids=_ids)
def test_no_suite_key_or_private_file_was_committed_alongside(sample):
    """The one mistake that would quietly invalidate every score a suite ever produced."""
    for dirpath, dirnames, filenames in os.walk(sample):
        assert "_key" not in dirnames and "_answers" not in dirnames, dirpath
        for name in filenames:
            assert not name.endswith(".hex"), os.path.join(dirpath, name)
            with open(os.path.join(dirpath, name), "rb") as f:
                head = f.read(4096)
            assert b"key.hex" not in head, name


def test_the_samples_index_lists_what_is_actually_there():
    index = os.path.join(ROOT, "samples", "README.md")
    with open(index) as f:
        text = f.read()
    for sample in SAMPLES:
        assert os.path.basename(sample.rstrip(os.sep)) in text


def test_windows_gallery_refuses_same_basename_at_an_unproved_target_path(tmp_path):
    """Gallery truth must not learn a resident path from the reference being checked."""
    from artifactforge.artifacts.shell_link import (
        ShellLinkTimestamps,
        build_shell_link,
        parse_shell_link,
    )

    source = Path(ROOT) / "samples" / "01-windows-dropper"
    sample = tmp_path / "windows"
    shutil.copytree(source, sample)
    link_path = sample / "ArtifactForgeMaintenance.lnk"
    observed = parse_shell_link(link_path.read_bytes())
    basename = observed.target_path.rsplit("\\", 1)[-1]
    link_path.write_bytes(
        build_shell_link(
            rf"C:\Unproved\{basename}",
            observed.display_name,
            observed.target_size,
            timestamps=ShellLinkTimestamps(
                observed.creation_filetime,
                observed.access_filetime,
                observed.write_filetime,
            ),
            volume_serial=observed.volume_serial,
            volume_label=observed.volume_label,
        )
    )

    with pytest.raises(ValueError, match="independent Prefetch path"):
        _load_sample_writer()._windows_evidence(os.fspath(sample))


def test_windows_gallery_refuses_task_same_basename_at_an_unproved_target_path(tmp_path):
    """Task truth must not learn a resident path from the reference being checked."""
    from artifactforge.artifacts.windows_task import (
        build_scheduled_task_xml,
        parse_scheduled_task_xml,
    )

    source = Path(ROOT) / "samples" / "01-windows-dropper"
    sample = tmp_path / "windows"
    shutil.copytree(source, sample)
    task_path = sample / "ArtifactForgeMaintenance.task.xml"
    observed = parse_scheduled_task_xml(task_path.read_bytes())
    basename = observed.command.rsplit("\\", 1)[-1]
    unproved = rf"C:\Unproved\{basename}"
    task_path.write_bytes(
        build_scheduled_task_xml(
            observed.task_name,
            unproved,
            resident_pe_paths=(unproved,),
            version=observed.version,
        )
    )

    with pytest.raises(ValueError, match="independent Prefetch path"):
        _load_sample_writer()._windows_evidence(os.fspath(sample))


def test_windows_gallery_reports_missing_persisted_prefetch_as_a_profile_error(tmp_path):
    source = Path(ROOT) / "samples" / "01-windows-dropper"
    sample = tmp_path / "windows"
    shutil.copytree(source, sample)
    answers = json.loads((sample / "ARTIFACT_ANSWERS.json").read_bytes())
    persisted_name = answers["derived_evidence"]["persisted"]["name"].upper()
    matches = tuple(sample.glob(f"{persisted_name}-*.pf"))
    assert len(matches) == 1
    matches[0].unlink()

    with pytest.raises(ValueError, match="persisted PE has no independent Prefetch path"):
        _load_sample_writer()._windows_evidence(os.fspath(sample))


@pytest.mark.parametrize("sample", SAMPLES, ids=_ids)
def test_the_sample_readme_quotes_the_bytes_that_are_committed(sample):
    """The pasted parser output has to describe these files, not an earlier generation."""
    with open(os.path.join(sample, "README.md")) as f:
        readme = f.read()
    for file in inventory_regular_files(sample, capture_bytes=True):
        name = file.relative_path
        if name in ("README.md", "ARTIFACT_ANSWERS.json"):
            continue
        data = file.data
        assert data is not None
        head = data[:4]
        if name.casefold().endswith((".task.xml", ".lnk")):
            assert name in readme, f"{name} is committed but the README does not mention it"
        if head[:2] == b"MZ" or head == b"\xcf\xfa\xed\xfe":
            digest = hashlib.sha256(data).hexdigest()
            assert name in readme, f"{name} is committed but the README does not mention it"
            if head[:2] == b"MZ":
                assert digest[:16] in readme, f"{name}'s digest in the README is stale"
