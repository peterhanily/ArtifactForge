# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Public macOS builders fail closed at the raw-oracle and semantic-profile boundary."""
from __future__ import annotations

import pytest

from artifactforge.artifacts import macos
from artifactforge.gates.oracles import (
    SQLiteWireProfile,
    loads_binary_plist,
    loads_sqlite,
)


KNOWLEDGE = [
    ("com.example.one", 100.0, 101.0),
    ("com.example.two", 200.0, 201.0),
    ("com.example.three", 300.0, 301.0),
]
TCC = [
    ("com.example.one", "kTCCServiceCamera", 2, 1_705_294_800),
    ("com.example.two", "kTCCServiceMicrophone", 2, 1_705_294_800),
    ("com.example.three", "kTCCServiceCamera", 0, 1_705_294_800),
    ("com.example.four", "kTCCServiceMicrophone", 0, 1_705_294_800),
]
QUARANTINE = [
    (
        f"00000000-0000-4000-8000-{index:012X}",
        "Safari",
        f"https://download.example/item-{index}.dmg",
        "https://download.example/files",
        700_000_000.0,
    )
    for index in range(1, 6)
]


class _OneShot:
    def __init__(self, rows):
        self.rows = rows
        self.iterations = 0

    def __iter__(self):
        self.iterations += 1
        if self.iterations > 1:
            raise AssertionError("builder iterated input more than once")
        yield from self.rows


@pytest.mark.parametrize(
    ("builder", "rows"),
    [
        (macos.build_knowledgec, KNOWLEDGE),
        (macos.build_tcc, TCC),
        (macos.build_quarantine_events, QUARANTINE),
    ],
)
def test_sqlite_builders_materialize_one_shot_inputs_once_and_stay_in_raw_subset(
    builder, rows
):
    one_shot = _OneShot(rows)
    data = builder(one_shot)
    assert one_shot.iterations == 1
    assert data == builder(rows)
    assert loads_sqlite(
        data, wire_profile=SQLiteWireProfile.ARTIFACTFORGE_OWNED_V1
    ).tables


@pytest.mark.parametrize(
    ("builder", "rows"),
    [
        (macos.build_knowledgec, []),
        (macos.build_knowledgec, KNOWLEDGE * 3),
        (macos.build_tcc, "not rows"),
        (macos.build_tcc, [("too", "short")]),
        (macos.build_quarantine_events, [QUARANTINE[0] + ("extra",)]),
    ],
)
def test_sqlite_builders_reject_unbounded_or_malformed_row_shapes(builder, rows):
    with pytest.raises(ValueError):
        builder(rows)


def test_row_bound_stops_an_unending_iterator_after_the_ninth_pull():
    class Unending:
        def __init__(self):
            self.pulls = 0

        def __iter__(self):
            return self

        def __next__(self):
            self.pulls += 1
            return (f"com.example.item{self.pulls}", 1.0, 2.0)

    rows = Unending()
    with pytest.raises(ValueError, match="1..8 rows"):
        macos.build_knowledgec(rows)
    assert rows.pulls == 9


@pytest.mark.parametrize(
    "rows",
    [
        [("com.example.one", True, 2.0)],
        [("com.example.one", float("nan"), 2.0)],
        [("com.example.one", 2.0, float("inf"))],
        [("com.example.one", 2.0, 1.0)],
        [("com.example.\N{LATIN SMALL LETTER E WITH ACUTE}", 1.0, 2.0)],
    ],
)
def test_knowledge_builder_rejects_values_outside_its_leaf_profile(rows):
    with pytest.raises(ValueError):
        macos.build_knowledgec(rows)


def test_knowledge_builder_allows_repeated_bundle_for_distinct_intervals():
    rows = [("com.example.one", 1.0, 2.0), ("com.example.one", 3.0, 4.0)]
    assert loads_sqlite(
        macos.build_knowledgec(rows),
        wire_profile=SQLiteWireProfile.ARTIFACTFORGE_OWNED_V1,
    ).tables


@pytest.mark.parametrize(
    "rows",
    [
        [("com.example.one", "kTCCServiceCamera", True, 1)],
        [("com.example.one", "kTCCServiceCamera", 1, 1)],
        [("com.example.one", "kTCCServiceCamera", 2, True)],
        [("com.example.one", "kTCCServiceCamera", 2, 0)],
    ],
)
def test_tcc_builder_rejects_ambiguous_types_and_values(rows):
    with pytest.raises(ValueError):
        macos.build_tcc(rows)


def test_tcc_builder_allows_one_client_to_hold_distinct_services():
    rows = [
        ("com.example.one", "kTCCServiceCamera", 2, 1),
        ("com.example.one", "kTCCServiceMicrophone", 0, 1),
    ]
    assert loads_sqlite(
        macos.build_tcc(rows),
        wire_profile=SQLiteWireProfile.ARTIFACTFORGE_OWNED_V1,
    ).tables


@pytest.mark.parametrize(
    "replacement",
    [
        ("00000000-0000-4000-8000-000000000001", "Safari", "http://x.example/a", "https://x.example/", 1.0),
        ("00000000-0000-4000-8000-000000000001", "Safari", "https://u:p@x.example/a", "https://x.example/", 1.0),
        ("00000000-0000-4000-8000-000000000001", "Safari", "https://x.example/a#f", "https://x.example/", 1.0),
        ("00000000-0000-4000-8000-000000000001", "Safari", "https://x.example/a", "https://x.example/", -1.0),
        ("00000000-0000-4000-8000-000000000001", "Safari", "https://x.example/a", "https://x.example/", float("nan")),
        ("00000000-0000-1000-8000-000000000001", "Safari", "https://x.example/a", "https://x.example/", 1.0),
        ("00000000-0000-4000-8000-00000000000a", "Safari", "https://x.example/a", "https://x.example/", 1.0),
    ],
)
def test_quarantine_builder_rejects_non_profile_uuid_url_and_time(replacement):
    with pytest.raises(ValueError):
        macos.build_quarantine_events([replacement])


def test_quarantine_builder_rejects_duplicate_identifiers():
    with pytest.raises(ValueError, match="duplicated"):
        macos.build_quarantine_events([QUARANTINE[0], QUARANTINE[0]])


@pytest.mark.parametrize(
    "path",
    ["/", "/a//b", "/a/", "//server/path", "/a\\b", "/a/./b", "/a/../b", "relative"],
)
def test_launchagent_builder_rejects_paths_the_gate_cannot_profile(path):
    with pytest.raises(ValueError, match="absolute normal POSIX path"):
        macos.build_launch_agent("com.example.agent", path)


@pytest.mark.parametrize("label", ["a/b", ".", "..", ".hidden", "Label", "com.example"])
def test_launchagent_builder_requires_a_visible_reverse_dns_filename_label(label):
    with pytest.raises(ValueError, match="reverse-DNS"):
        macos.build_launch_agent(label, "/opt/example/agent")


@pytest.mark.parametrize("run_at_load", [False, 0, 1, None])
def test_launchagent_builder_only_emits_the_persistence_profile(run_at_load):
    with pytest.raises(ValueError, match="must be true"):
        macos.build_launch_agent("com.example.agent", "/opt/example/agent", run_at_load)


def test_launchagent_builder_stays_in_the_raw_binary_plist_subset():
    data = macos.build_launch_agent("com.example.agent", "/opt/example/agent")
    parsed = loads_binary_plist(data)
    assert parsed["RunAtLoad"] is True
    assert parsed["StartInterval"] == 3600


def test_sqlite_writer_is_pure_and_does_not_depend_on_a_filesystem_path(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("owned SQLite writer attempted filesystem access")

    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr("os.open", forbidden)
    assert macos.build_knowledgec(KNOWLEDGE) == macos.build_knowledgec(KNOWLEDGE)
