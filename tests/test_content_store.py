# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Hostile filesystem tests for the content-addressed cache."""
from __future__ import annotations

import hashlib
import os
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import artifactforge.content.store as content_store
from artifactforge.content import ContentStore


pytestmark = pytest.mark.skipif(
    not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"),
    reason="secure ContentStore I/O requires no-follow directory descriptors",
)


def _cache_entries(cache: Path) -> list[str]:
    return sorted(path.name for path in cache.iterdir())


def test_cache_hit_reuses_only_verified_bytes(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    store = ContentStore("content-store-test", str(cache))
    first = store.materialize("pe:verified-hit")
    first_inode = os.stat(first.path).st_ino

    second = store.materialize("pe:verified-hit")

    assert second == first
    assert os.stat(second.path).st_ino == first_inode
    assert Path(second.path).read_bytes() == second.bytes
    assert _cache_entries(cache) == [second.sha256]


def test_relative_cache_returns_a_stable_absolute_path_after_chdir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    construction_directory = tmp_path / "construction"
    later_directory = tmp_path / "later"
    construction_directory.mkdir()
    later_directory.mkdir()
    monkeypatch.chdir(construction_directory)
    store = ContentStore("content-store-test", "cache")

    monkeypatch.chdir(later_directory)
    content = store.materialize("pe:relative-cache-after-chdir")

    expected = construction_directory / "cache" / content.sha256
    assert Path(content.path) == expected
    assert Path(content.path).is_absolute()
    assert expected.read_bytes() == content.bytes


def test_corrupt_cache_entry_is_atomically_repaired(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    store = ContentStore("content-store-test", str(cache))
    content = store.materialize("pe:repair-corruption")
    path = Path(content.path)
    corrupt_inode = os.stat(path).st_ino
    path.write_bytes(b"not the content named by this digest")

    repaired = store.materialize("pe:repair-corruption")

    assert Path(repaired.path).read_bytes() == repaired.bytes
    assert hashlib.sha256(Path(repaired.path).read_bytes()).hexdigest() == repaired.sha256
    assert os.stat(repaired.path).st_ino != corrupt_inode
    assert stat.S_IMODE(os.stat(repaired.path).st_mode) == 0o600
    assert _cache_entries(cache) == [repaired.sha256]


def test_cache_symlink_is_replaced_without_touching_its_target(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    store = ContentStore("content-store-test", str(cache))
    content = store.materialize("pe:symlink-entry")
    path = Path(content.path)
    victim = tmp_path / "victim"
    victim.write_bytes(b"outside the cache")
    path.unlink()
    path.symlink_to(victim)

    repaired = store.materialize("pe:symlink-entry")

    assert victim.read_bytes() == b"outside the cache"
    assert not Path(repaired.path).is_symlink()
    assert Path(repaired.path).read_bytes() == repaired.bytes


def test_stat_to_open_symlink_swap_cannot_escape_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache = tmp_path / "cache"
    store = ContentStore("content-store-test", str(cache))
    content = store.materialize("pe:stat-open-race")
    victim = tmp_path / "victim"
    victim.write_bytes(b"must remain untouched")
    real_open = content_store.os.open
    raced = False

    def swap_before_open(
        path: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal raced
        if not raced and path == content.sha256 and dir_fd is not None:
            raced = True
            assert flags & os.O_NOFOLLOW
            os.unlink(path, dir_fd=dir_fd)
            os.symlink(victim, path, dir_fd=dir_fd)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(content_store.os, "open", swap_before_open)

    repaired = store.materialize("pe:stat-open-race")

    assert raced
    assert victim.read_bytes() == b"must remain untouched"
    assert not Path(repaired.path).is_symlink()
    assert Path(repaired.path).read_bytes() == repaired.bytes


def test_hardlinked_cache_entry_is_not_trusted_or_mutated(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    store = ContentStore("content-store-test", str(cache))
    content = store.materialize("pe:hardlink-entry")
    path = Path(content.path)
    outside = tmp_path / "outside"
    outside.write_bytes(content.bytes)
    outside_inode = os.stat(outside).st_ino
    path.unlink()
    os.link(outside, path)
    assert os.stat(path).st_nlink == 2

    repaired = store.materialize("pe:hardlink-entry")

    assert os.stat(outside).st_ino == outside_inode
    assert os.stat(outside).st_nlink == 1
    assert os.stat(repaired.path).st_ino != outside_inode
    assert outside.read_bytes() == content.bytes


def test_constructor_rejects_a_symlink_cache_root(tmp_path: Path) -> None:
    real_cache = tmp_path / "real-cache"
    real_cache.mkdir()
    link = tmp_path / "cache-link"
    link.symlink_to(real_cache, target_is_directory=True)

    with pytest.raises(RuntimeError, match="cache path is not a real directory"):
        ContentStore("content-store-test", str(link))


def test_payload_must_match_its_requested_content_address(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    store = ContentStore("content-store-test", str(cache))

    with pytest.raises(ValueError, match="does not match payload SHA256"):
        store._store("0" * 64, b"different bytes")

    assert _cache_entries(cache) == []


def test_short_os_writes_are_completed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_write = content_store.os.write

    def short_write(descriptor: int, data: bytes | memoryview) -> int:
        return real_write(descriptor, data[:7])

    monkeypatch.setattr(content_store.os, "write", short_write)
    store = ContentStore("content-store-test", str(tmp_path / "cache"))

    content = store.materialize("pe:short-write")

    assert Path(content.path).read_bytes() == content.bytes


def test_publication_fsyncs_file_and_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    synced_types: list[int] = []
    real_fsync = content_store.os.fsync

    def recording_fsync(descriptor: int) -> None:
        synced_types.append(os.fstat(descriptor).st_mode)
        real_fsync(descriptor)

    monkeypatch.setattr(content_store.os, "fsync", recording_fsync)
    store = ContentStore("content-store-test", str(tmp_path / "cache"))

    store.materialize("pe:durable-publication")

    assert any(stat.S_ISREG(mode) for mode in synced_types)
    assert any(stat.S_ISDIR(mode) for mode in synced_types)


def test_publication_uses_only_descriptor_anchored_cache_chmod(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []
    real_chmod = content_store.os.chmod

    def record_safe_chmod(path, mode, *, dir_fd=None, follow_symlinks=True):
        calls.append((path, mode, dir_fd, follow_symlinks))
        assert path == "cache"
        assert mode == 0o700
        assert isinstance(dir_fd, int)
        assert follow_symlinks is False
        return real_chmod(
            path,
            mode,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(content_store.os, "chmod", record_safe_chmod)
    store = ContentStore("content-store-test", str(tmp_path / "cache"))

    content = store.materialize("pe:descriptor-chmod")

    assert len(calls) == 1
    assert stat.S_IMODE(os.stat(content.path).st_mode) == 0o600


def test_concurrent_writers_converge_on_one_verified_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache = tmp_path / "cache"
    stores = [ContentStore("content-store-test", str(cache)) for _ in range(8)]
    payload = b"the same content from every concurrent writer"
    digest = hashlib.sha256(payload).hexdigest()
    (cache / digest).write_bytes(b"force every writer down the repair path")
    barrier = threading.Barrier(len(stores))
    real_replace = content_store.os.replace

    def synchronised_replace(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        assert destination == digest
        barrier.wait(timeout=15)
        real_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(content_store.os, "replace", synchronised_replace)
    with ThreadPoolExecutor(max_workers=len(stores)) as executor:
        paths = list(executor.map(lambda store: store._store(digest, payload), stores))

    assert paths == [str(cache / digest)] * len(stores)
    assert (cache / digest).read_bytes() == payload
    assert stat.S_IMODE(os.stat(cache / digest).st_mode) == 0o600
    assert _cache_entries(cache) == [digest]


def test_cache_root_replacement_is_detected_after_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache = tmp_path / "cache"
    moved = tmp_path / "detached-cache"
    store = ContentStore("content-store-test", str(cache))
    real_replace = content_store.os.replace

    def replace_then_swap_root(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        real_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )
        cache.rename(moved)
        cache.mkdir()

    monkeypatch.setattr(content_store.os, "replace", replace_then_swap_root)

    with pytest.raises(RuntimeError, match="cache directory binding changed"):
        store.materialize("pe:root-swap")

    assert _cache_entries(cache) == []
    assert len(_cache_entries(moved)) == 1


def test_cache_hit_rechecks_root_after_the_final_entry_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache = tmp_path / "cache"
    moved = tmp_path / "detached-cache"
    store = ContentStore("content-store-test", str(cache))
    content = store.materialize("pe:cache-hit-final-binding")
    real_entry_matches = content_store._entry_matches
    calls = 0

    def read_then_swap_root(*args, **kwargs):
        nonlocal calls
        calls += 1
        matched = real_entry_matches(*args, **kwargs)
        if calls == 2:
            cache.rename(moved)
            cache.mkdir()
        return matched

    monkeypatch.setattr(content_store, "_entry_matches", read_then_swap_root)

    with pytest.raises(RuntimeError, match="cache directory binding changed"):
        store.materialize("pe:cache-hit-final-binding")

    assert calls == 2
    assert not (cache / content.sha256).exists()
    assert (moved / content.sha256).read_bytes() == content.bytes


def test_post_publication_byte_mutation_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache = tmp_path / "cache"
    store = ContentStore("content-store-test", str(cache))
    real_replace = content_store.os.replace

    def replace_then_corrupt(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        real_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )
        assert dst_dir_fd is not None
        descriptor = os.open(destination, os.O_WRONLY | os.O_TRUNC, dir_fd=dst_dir_fd)
        try:
            os.write(descriptor, b"corrupt after rename")
        finally:
            os.close(descriptor)

    monkeypatch.setattr(content_store.os, "replace", replace_then_corrupt)

    with pytest.raises(RuntimeError, match="published content failed byte"):
        store.materialize("pe:post-publication-corruption")

    entries = _cache_entries(cache)
    assert len(entries) == 1
    assert (cache / entries[0]).read_bytes() == b"corrupt after rename"
