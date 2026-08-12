# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""A story is the incident shape a v2 recipe asks for.

The enumeration is closed, so these checks own the two ways it could rot: a story nobody can
build, and a builder nothing can select.  They also pin the story into the derivation, because
a selector that did not change the bytes would be decoration.
"""

from __future__ import annotations

import pathlib
import tempfile

import pytest

from artifactforge.fixture.model_v2 import (
    STORIES_V2,
    FixtureSpecV2,
    FixtureV2ValidationError,
    ProfileSpecV2,
)
from artifactforge.fixture import operations
from artifactforge.fixture.operations import (
    FixtureUsageError,
    build_fixture,
    verify_fixture,
)

FAMILY_PROFILES = {
    "windows": "windows-loose-v2",
    "macos": "macos-14-loose-v2",
    "linux": "linux-glibc-x86_64-loose-v2",
}


def _spec(family, story, *, seed_hex="ab" * 32):
    return FixtureSpecV2.create(
        fixture_id="story-probe",
        family=family,
        story=story,
        profile=ProfileSpecV2(
            id=FAMILY_PROFILES[family], hostname=f"{family}-01", username="v"
        ),
        seed_hex=seed_hex,
    )


@pytest.mark.parametrize("story", sorted(STORIES_V2))
def test_every_registered_story_builds(story):
    """No story may be selectable without a builder behind it."""
    family = STORIES_V2[story]
    with tempfile.TemporaryDirectory() as work:
        manifest = build_fixture(_spec(family, story), pathlib.Path(work) / "fixture")
    assert manifest.payload.file_count > 0
    assert manifest.recipe.story == story


def test_an_unregistered_story_is_refused_before_any_build():
    with pytest.raises(FixtureV2ValidationError, match="spec.story must be one of"):
        _spec("windows", "windows-not-a-story-v1")


@pytest.mark.parametrize(
    ("family", "story"),
    [
        ("windows", "linux-autostart-v1"),
        ("macos", "windows-dropper-v1"),
        ("linux", "macos-quarantined-app-v1"),
    ],
)
def test_a_story_cannot_cross_families(family, story):
    with pytest.raises(FixtureV2ValidationError, match="belongs to"):
        _spec(family, story)


def test_a_story_without_a_builder_fails_closed(monkeypatch):
    """STORIES_V2 and the dispatch are separate; a story that outran its builder must not
    silently fall through to another family's scene."""
    monkeypatch.setitem(STORIES_V2, "windows-unbuilt-v1", "windows")
    spec = _spec("windows", "windows-unbuilt-v1")
    with pytest.raises(FixtureUsageError, match="no registered builder"):
        operations._build_scene(
            spec, store=None, scene_dir=pathlib.Path("."), staging=pathlib.Path(".")
        )


def test_the_story_is_bound_into_the_recipe_and_its_derivation(monkeypatch):
    """Changing only the story must move the clock and the recipe digest."""
    dropper = _spec("windows", "windows-dropper-v1")
    monkeypatch.setitem(STORIES_V2, "windows-alternate-v1", "windows")
    alternate = _spec("windows", "windows-alternate-v1")

    assert dropper.seed_hex == alternate.seed_hex
    assert dropper.fixture_id == alternate.fixture_id
    assert dropper.profile == alternate.profile
    assert dropper.causal_clock != alternate.causal_clock
    assert dropper.recipe_sha256 != alternate.recipe_sha256
    assert b'"story":"windows-dropper-v1"' in dropper.canonical_bytes()


def test_a_recipe_without_a_story_is_rejected():
    mapping = _spec("linux", "linux-autostart-v1").to_mapping()
    del mapping["story"]
    with pytest.raises(FixtureV2ValidationError, match="story"):
        FixtureSpecV2.from_mapping(mapping)


def test_the_schema_enumerates_exactly_the_registered_stories():
    import json

    schema = json.loads(
        (
            pathlib.Path(operations.__file__).parent
            / "schemas"
            / "fixture-spec-v2.schema.json"
        ).read_text()
    )
    assert sorted(schema["properties"]["story"]["enum"]) == sorted(STORIES_V2)
    assert "story" in schema["required"]

    def allowed(constraint):
        return sorted(constraint["enum"]) if "enum" in constraint else [constraint["const"]]

    bound = {
        clause["if"]["properties"]["family"]["const"]: allowed(
            clause["then"]["properties"]["story"]
        )
        for clause in schema["allOf"]
    }
    expected = {}
    for story, family in STORIES_V2.items():
        expected.setdefault(family, []).append(story)
    assert bound == {family: sorted(stories) for family, stories in expected.items()}


def _download_only(tmp_path):
    spec = _spec("windows", "windows-download-only-v1", seed_hex="7c" * 32)
    root = tmp_path / "download-only"
    return spec, root, build_fixture(spec, root)


def test_download_only_serves_arrival_evidence_and_nothing_else(tmp_path):
    _spec_, root, manifest = _download_only(tmp_path)
    guest_paths = sorted(node.guest_path for node in manifest.payload.files)
    assert guest_paths == [
        "C:\\Program Files\\gimp.exe",
        "C:\\Users\\v\\AppData\\Local\\Chromium\\User Data\\Default\\History",
        "C:\\Users\\v\\Downloads\\taskeng_x.exe",
        "C:\\Windows\\System32\\powershell.exe",
    ]
    marked = [
        node
        for node in manifest.payload.files
        if any(blob.name == "Zone.Identifier" for blob in node.metadata.streams)
    ]
    assert [node.guest_path for node in marked] == [
        "C:\\Users\\v\\Downloads\\taskeng_x.exe"
    ]
    assert verify_fixture(root, assurance=True).ok


def test_download_only_manifest_never_leaks_the_withheld_surfaces(tmp_path):
    _spec_, _root, manifest = _download_only(tmp_path)
    payload = manifest.canonical_bytes()
    for token in (b'"join"', b'"answers"', b'"absent_surfaces"', b'"pivots"'):
        assert token not in payload


@pytest.mark.parametrize(
    ("label", "guest_path"),
    [
        ("Task definition", "C:\\Windows\\System32\\Tasks\\ArtifactForge\\Maintenance"),
        (
            "Shell Link",
            "C:\\Users\\v\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\"
            "ArtifactForgeMaintenance.lnk",
        ),
        ("Amcache hive", "C:\\Windows\\AppCompat\\Programs\\Amcache.hve"),
        ("SOFTWARE hive", "C:\\Windows\\System32\\config\\SOFTWARE"),
        ("Prefetch record", "C:\\Windows\\Prefetch\\TASKENG_X.EXE-01234567.pf"),
    ],
)
def test_each_withheld_surface_turns_the_absence_claim_red(tmp_path, label, guest_path):
    """The story's claim is what is missing, so planting any one surface must fail it."""
    from artifactforge.fixture import operations

    _spec_, _root, manifest = _download_only(tmp_path)
    planted = manifest.payload.files[0].__class__(
        **{
            **{
                field: getattr(manifest.payload.files[0], field)
                for field in manifest.payload.files[0].__dataclass_fields__
            },
            "guest_path": guest_path,
        }
    )
    object.__setattr__(
        manifest.payload, "files", (*manifest.payload.files, planted)
    )
    failures = operations._windows_execution_surface_absences(manifest)
    assert len(failures) == 1
    assert label in failures[0]
    assert guest_path in failures[0]


def test_an_untouched_download_only_manifest_declares_no_absence_failure(tmp_path):
    from artifactforge.fixture import operations

    _spec_, _root, manifest = _download_only(tmp_path)
    assert operations._windows_execution_surface_absences(manifest) == []


def _download_only_projection_case(root):
    """Build the scene directly so its private truth can be tampered with before projection."""
    from artifactforge.compose.fixture_scene_v2 import project_fixture_scene_v2
    from artifactforge.compose.scene import build_windows_download_only_scene
    from artifactforge.content import ContentStore
    from artifactforge.inventory import inventory_regular_files
    from artifactforge.model import windows_profile

    host = windows_profile()
    spec = FixtureSpecV2.create(
        fixture_id="absence-probe",
        family="windows",
        story="windows-download-only-v1",
        profile=ProfileSpecV2(
            id="windows-loose-v2", hostname=host.hostname, username=host.username
        ),
        seed_hex="7c" * 32,
    )
    scene = build_windows_download_only_scene(
        ContentStore("download-only-tests", str(root / "content")),
        skey=bytes.fromhex(spec.seed_hex),
        profile=host,
        scene_dir=str(root / "scene"),
        staging_dir=str(root / "staging"),
        causal_clock=spec.causal_clock,
    )
    loose = {
        item.relative_path: item.data
        for item in inventory_regular_files(scene.directory, capture_bytes=True)
    }
    return spec, scene, loose, project_fixture_scene_v2


@pytest.mark.parametrize(
    "declared",
    [
        None,
        [],
        ["amcache", "prefetch", "run-key", "scheduled-task"],
        ["prefetch", "amcache", "run-key", "scheduled-task", "shell-link"],
        ["amcache", "prefetch", "run-key", "scheduled-task", "shell-link", "extra"],
        "amcache",
    ],
)
def test_the_scene_must_declare_the_exact_absent_surfaces(tmp_path, declared):
    """A withheld surface only counts as withheld if the scene said so up front."""
    from artifactforge.compose.fixture_scene_v2 import FixtureSceneProjectionError

    spec, scene, loose, project = _download_only_projection_case(tmp_path)
    if declared is None:
        del scene.join["absent_surfaces"]
    else:
        scene.join["absent_surfaces"] = declared
    with pytest.raises(FixtureSceneProjectionError, match="exact absent execution surfaces"):
        project(spec=spec, scene=scene, loose_files=loose)


@pytest.mark.parametrize("key", ["scheduled_task", "shell_link", "persisted", "prefetch"])
def test_the_scene_may_not_smuggle_execution_truth(tmp_path, key):
    from artifactforge.compose.fixture_scene_v2 import FixtureSceneProjectionError

    spec, scene, loose, project = _download_only_projection_case(tmp_path)
    scene.join[key] = {"source": "smuggled"}
    with pytest.raises(FixtureSceneProjectionError, match="carries execution truth"):
        project(spec=spec, scene=scene, loose_files=loose)


def test_the_untampered_download_only_scene_projects(tmp_path):
    spec, scene, loose, project = _download_only_projection_case(tmp_path)
    plan = project(spec=spec, scene=scene, loose_files=loose)
    assert len(plan.file_nodes) == 4


@pytest.mark.parametrize(
    "source", ["Amcache.hve", "Software.run.hive", "ArtifactForgeMaintenance.task.xml",
               "ArtifactForgeMaintenance.lnk", "TASKENG_X.EXE-01234567.pf"]
)
def test_serving_an_execution_artifact_is_refused_even_with_a_clean_declaration(tmp_path, source):
    """The declaration and the served bytes are checked separately: a scene that declares the
    absences and then ships one of them anyway must still be refused."""
    from artifactforge.compose.fixture_scene_v2 import FixtureSceneProjectionError

    spec, scene, loose, project = _download_only_projection_case(tmp_path)
    scene.artifacts = sorted([*scene.artifacts, source])
    loose = {**loose, source: b"regf" + b"\0" * 60}
    with pytest.raises(FixtureSceneProjectionError, match="serves execution artifacts"):
        project(spec=spec, scene=scene, loose_files=loose)
