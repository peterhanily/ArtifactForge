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
import json
import os

import pytest

from artifactforge.gates import identity, inertness, validity
from artifactforge.inventory import inventory_regular_files

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = sorted(glob.glob(os.path.join(ROOT, "samples", "*", "")))

pytestmark = pytest.mark.skipif(not SAMPLES, reason="no samples committed")


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
def test_the_committed_answer_key_still_matches_the_committed_bytes(sample):
    """The join is re-derived from the files as committed, not from the generator."""
    pytest.importorskip("regipy")
    truth = _ground_truth(sample)
    report = identity.run(sample, truth["join"])
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
        if head[:2] == b"MZ" or head == b"\xcf\xfa\xed\xfe":
            digest = hashlib.sha256(data).hexdigest()
            assert name in readme, f"{name} is committed but the README does not mention it"
            if head[:2] == b"MZ":
                assert digest[:16] in readme, f"{name}'s digest in the README is stale"
