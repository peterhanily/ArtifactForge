# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""One-shot benchmark attempt ledger with retirement-gated feedback.

The library enforces that the evaluator-private ledger lives outside the evaluator suite.
Deployment must additionally keep that ledger outside the solver's filesystem trust domain;
the solver-export boundary is an orchestration property that this API cannot inspect.
Exclusive claim creation happens before the reveal path is opened, so an unreadable, malformed
or mismatched reveal consumes the attempt just like a scored reveal.

This is a local filesystem enforcement boundary, not an external timestamp, append-only log or
proof of solver isolation.  An evaluator that copies the suite or designates multiple ledger
roots can still manufacture multiple attempts; reportability therefore remains pending an
independent witness over the designated root and its terminal record.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat

from artifactforge import suite
from artifactforge.bench.benchmark import normalize
from artifactforge.bench.submission import (
    MAX_PRECOMMIT_BYTES,
    MAX_SUBMISSION_BYTES,
    parse_precommit,
    parse_submission,
)
from artifactforge.inventory import (
    InventoryError,
    directory_entry_matches_descriptor,
    open_real_directory,
    open_real_directory_at,
    remove_pinned_directory_at,
    rename_directory_no_replace,
)


ACCEPTANCE_FILE = "acceptance.json"
PRECOMMIT_FILE = "precommit.json"
CLAIM_FILE = "claim.json"
RESULT_FILE = "result.private.json"
RECEIPT_FILE = "receipt.json"
RETIREMENT_FILE = "retirement.json"
LOCK_FILE = "operation.lock"
LOCK_PAYLOAD = b"artifactforge-benchmark-attempt-operation-lock-v1\n"

ACCEPTANCE_SCHEMA = "artifactforge-benchmark-attempt-acceptance-v1"
CLAIM_SCHEMA = "artifactforge-benchmark-attempt-claim-v1"
RESULT_SCHEMA = "artifactforge-benchmark-attempt-private-result-v1"
RECEIPT_SCHEMA = "artifactforge-benchmark-attempt-receipt-v1"
RETIREMENT_SCHEMA = "artifactforge-benchmark-attempt-retirement-v1"
REPORT_SCHEMA = "artifactforge-benchmark-attempt-retired-report-v1"
MAX_LEDGER_RECORD_BYTES = 4 * 1024 * 1024
ATTEMPT_TRUST = (
    "LOCAL SELF-ATTESTATION ONLY: exclusive files enforce one claim in this designated "
    "ledger root; a local owner can still copy, delete or rewrite state, and the chain does "
    "not prove that the evaluator was not copied, that another root was not designated, or "
    "that an external witness observed it."
)
WITHHELD_RECEIPT_NOTICE = (
    "Attempt consumed. Detailed validity and score feedback are withheld from this receipt "
    "until local-ledger retirement; the plaintext private result remains visible to the "
    "ledger owner."
)
RETIRED_REPORT_NOTICE = (
    "NOT REPORTABLE: retirement releases local feedback, but this result remains pending "
    "independent witness attestation that this was the uniquely designated ledger root and "
    "that the local self-attestation trust limitations were satisfied."
)
ATTEMPT_PLATFORM_NOTICE = (
    "Benchmark v3 live attempt ledgers require POSIX directory-descriptor operations and "
    "advisory file locking; Windows evaluators may verify detached retired reports but "
    "cannot create, consume, retire, or read a live ledger."
)
ATTEMPT_PLATFORM_SUPPORTED = os.name == "posix" and all(
    function in os.supports_dir_fd
    for function in (
        os.chmod,
        os.link,
        os.mkdir,
        os.open,
        os.rename,
        os.rmdir,
        os.stat,
        os.unlink,
    )
) and os.listdir in os.supports_fd

_ATTEMPT_ID = re.compile(r"^afa1_[a-z2-7]{26}$")
_SCENARIO_ID = re.compile(r"^af1_[a-z2-7]{16}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
)


class AttemptError(ValueError):
    """The attempt protocol input, filesystem boundary or record chain is invalid."""


class AttemptConsumedError(AttemptError):
    """The one allowed reveal claim already exists, even if later processing crashed."""


class AttemptNotRetiredError(AttemptError):
    """Detailed feedback was requested before the local-ledger retirement marker exists."""


class AttemptBusyError(AttemptError):
    """Another live process owns the ledger state-transition lock."""


class AttemptPlatformError(AttemptError):
    """The host cannot provide the live ledger's filesystem semantics."""


class _RevealRejected(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _transition_timestamp(*, not_before: str, transition: str) -> str:
    """Refuse a state transition while the local wall clock is behind its predecessor.

    Record hashes establish ordering, but the protocol also publishes self-attested wall-clock
    fields.  Refusing before publication avoids either manufacturing a clamped timestamp or
    creating a chain that its own verifier will later reject.
    """
    value = _timestamp()
    if value < not_before:
        raise AttemptError(
            f"cannot publish {transition}: local UTC clock predates the preceding record"
        )
    return value


def require_attempt_platform() -> None:
    """Fail closed before live state is touched on unsupported hosts."""
    if not ATTEMPT_PLATFORM_SUPPORTED:
        raise AttemptPlatformError(ATTEMPT_PLATFORM_NOTICE)


def _attempt_id() -> str:
    encoded = base64.b32encode(secrets.token_bytes(16)).decode("ascii").rstrip("=").lower()
    return "afa1_" + encoded


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _record(unsigned: dict) -> dict:
    record_id = _sha256(suite.canonical_public_bytes(unsigned))
    return {**unsigned, "record_id": record_id}


def _record_bytes(unsigned: dict) -> bytes:
    return suite.canonical_public_bytes(_record(unsigned))


def _parse_record(data: bytes, *, schema: str, fields: set[str], where: str) -> dict:
    if len(data) > MAX_LEDGER_RECORD_BYTES:
        raise AttemptError(
            f"{where} exceeds the {MAX_LEDGER_RECORD_BYTES}-byte record limit"
        )
    try:
        document = suite._strict_public_document(data, where)
        canonical = suite.canonical_public_bytes(document)
    except ValueError as exc:
        raise AttemptError(f"{where} is invalid: {exc}") from exc
    if data != canonical:
        raise AttemptError(f"{where} is not canonical JSON")
    if set(document) != fields | {"record_id"}:
        raise AttemptError(f"{where} has unknown or missing fields")
    if document.get("schema") != schema:
        raise AttemptError(f"{where} schema is unsupported")
    record_id = document.get("record_id")
    if not isinstance(record_id, str):
        raise AttemptError(f"{where} record_id is invalid")
    unsigned = dict(document)
    unsigned.pop("record_id")
    if record_id != _sha256(suite.canonical_public_bytes(unsigned)):
        raise AttemptError(f"{where} record_id does not bind its document")
    return document


def _require_timestamp(value: object, where: str) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise AttemptError(f"{where} timestamp is invalid")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise AttemptError(f"{where} timestamp is invalid") from exc
    return value


def _write_exclusive_record(root_fd: int, name: str, data: bytes) -> None:
    """Durably create one marker; a failed partial marker is deliberately never removed."""
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=root_fd)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise AttemptError(f"attempt record {name!r} is not a single-link regular file")
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while creating attempt record")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        named = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(named.st_mode)
            or (final.st_dev, final.st_ino) != (named.st_dev, named.st_ino)
            or final.st_size != len(data)
            or final.st_nlink != 1
            or (os.name != "nt" and stat.S_IMODE(final.st_mode) != 0o600)
        ):
            raise AttemptError(f"attempt record {name!r} changed while being secured")
        os.fsync(root_fd)
        secured = os.fstat(descriptor)
        secured_name = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if (
            (secured.st_dev, secured.st_ino)
            != (secured_name.st_dev, secured_name.st_ino)
            or secured.st_size != len(data)
            or secured.st_nlink != 1
            or (os.name != "nt" and stat.S_IMODE(secured.st_mode) != 0o600)
        ):
            raise AttemptError(f"attempt record {name!r} changed after durability sync")
    except FileExistsError:
        raise
    except AttemptError:
        raise
    except (NotImplementedError, OSError) as exc:
        raise AttemptError(f"cannot durably create attempt record {name!r}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _record_stage_prefix(name: str) -> str:
    return f".{name}.stage-"


def _unlink_regular_if_exact(root_fd: int, name: str, identity: tuple[int, int]) -> None:
    try:
        state = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if stat.S_ISREG(state.st_mode) and (state.st_dev, state.st_ino) == identity:
            os.unlink(name, dir_fd=root_fd)
    except OSError:
        pass


def _publish_atomic_record(root_fd: int, name: str, data: bytes) -> None:
    """Publish complete bytes atomically by no-replace hard link, then drop the stage link."""
    stage_name = _record_stage_prefix(name) + secrets.token_hex(16)
    stage_identity: tuple[int, int] | None = None
    linked = False
    try:
        _write_exclusive_record(root_fd, stage_name, data)
        stage = os.stat(stage_name, dir_fd=root_fd, follow_symlinks=False)
        stage_identity = (stage.st_dev, stage.st_ino)
        os.link(
            stage_name,
            name,
            src_dir_fd=root_fd,
            dst_dir_fd=root_fd,
            follow_symlinks=False,
        )
        linked = True
        final = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(final.st_mode)
            or (final.st_dev, final.st_ino) != stage_identity
            or final.st_size != len(data)
        ):
            raise AttemptError(f"attempt record {name!r} changed during atomic publication")
        os.fsync(root_fd)
        os.unlink(stage_name, dir_fd=root_fd)
        os.fsync(root_fd)
        secured = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if secured.st_nlink != 1 or (secured.st_dev, secured.st_ino) != stage_identity:
            raise AttemptError(f"attempt record {name!r} has an invalid final link state")
    except FileExistsError:
        if stage_identity is not None:
            _unlink_regular_if_exact(root_fd, stage_name, stage_identity)
        raise
    except AttemptError:
        if stage_identity is not None and not linked:
            _unlink_regular_if_exact(root_fd, stage_name, stage_identity)
        raise
    except (NotImplementedError, OSError) as exc:
        if stage_identity is not None and not linked:
            _unlink_regular_if_exact(root_fd, stage_name, stage_identity)
        raise AttemptError(f"cannot atomically publish attempt record {name!r}: {exc}") from exc


def _recover_record_stages(root_fd: int) -> None:
    """Finish only known complete link publications or discard never-published stages."""
    changed = False
    names = tuple(os.listdir(root_fd))
    for final_name in (CLAIM_FILE, RESULT_FILE, RECEIPT_FILE, RETIREMENT_FILE):
        prefix = _record_stage_prefix(final_name)
        for stage_name in (name for name in names if name.startswith(prefix)):
            try:
                staged = os.stat(stage_name, dir_fd=root_fd, follow_symlinks=False)
            except OSError as exc:
                raise AttemptError(f"cannot inspect attempt record stage {stage_name!r}: {exc}") from exc
            if not stat.S_ISREG(staged.st_mode):
                raise AttemptError(f"attempt record stage {stage_name!r} is not regular")
            try:
                final = os.stat(final_name, dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                final = None
            except OSError as exc:
                raise AttemptError(
                    f"cannot inspect staged attempt destination {final_name!r}: {exc}"
                ) from exc
            if final is not None and (
                not stat.S_ISREG(final.st_mode)
                or (final.st_dev, final.st_ino) != (staged.st_dev, staged.st_ino)
            ):
                raise AttemptError(
                    f"attempt record stage {stage_name!r} does not name its final inode"
                )
            os.unlink(stage_name, dir_fd=root_fd)
            changed = True
    if changed:
        os.fsync(root_fd)


@contextmanager
def _operation_lock(root_fd: int):
    """Hold the crash-released process lock across one complete ledger transition."""
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    locked = False
    try:
        descriptor = os.open(LOCK_FILE, flags, dir_fd=root_fd)
        opened = os.fstat(descriptor)
        named = os.stat(LOCK_FILE, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            or opened.st_size != len(LOCK_PAYLOAD)
            or (os.name != "nt" and stat.S_IMODE(opened.st_mode) != 0o600)
        ):
            raise AttemptError("attempt operation lock has an invalid carrier profile")
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.read(descriptor, len(LOCK_PAYLOAD) + 1) != LOCK_PAYLOAD:
            raise AttemptError("attempt operation lock bytes are invalid")
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            if os.name == "nt":  # pragma: no cover - Windows native lane is external
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except (BlockingIOError, OSError) as exc:
            raise AttemptBusyError("another process is transitioning this attempt") from exc
        secured = os.fstat(descriptor)
        secured_name = os.stat(LOCK_FILE, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(secured.st_mode)
            or secured.st_nlink != 1
            or (secured.st_dev, secured.st_ino)
            != (secured_name.st_dev, secured_name.st_ino)
            or secured.st_size != len(LOCK_PAYLOAD)
            or (os.name != "nt" and stat.S_IMODE(secured.st_mode) != 0o600)
        ):
            raise AttemptError("attempt operation lock changed while being acquired")
        _recover_record_stages(root_fd)
        yield
    finally:
        if descriptor >= 0 and locked:
            try:
                if os.name == "nt":  # pragma: no cover - Windows native lane is external
                    import msvcrt

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        if descriptor >= 0:
            os.close(descriptor)


def _create_staging_directory(parent_fd: int, parent: Path, final_name: str) -> tuple[Path, int]:
    """Create and hold a private sibling, cleaning only its exact inode on setup failure."""
    for _attempt in range(128):
        name = f".{final_name}.attempt-stage-{secrets.token_hex(16)}"
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        except OSError as exc:
            raise AttemptError(f"cannot create private attempt staging root: {exc}") from exc
        created: os.stat_result | None = None
        descriptor = -1
        try:
            created = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            os.chmod(name, 0o700, dir_fd=parent_fd, follow_symlinks=False)
            descriptor = open_real_directory_at(parent_fd, name)
            opened = os.fstat(descriptor)
            named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            os.fchmod(descriptor, 0o700)
            secured = os.fstat(descriptor)
            identities = {
                (created.st_dev, created.st_ino),
                (opened.st_dev, opened.st_ino),
                (named.st_dev, named.st_ino),
                (secured.st_dev, secured.st_ino),
            }
            if (
                len(identities) != 1
                or not stat.S_ISDIR(secured.st_mode)
                or (os.name != "nt" and stat.S_IMODE(secured.st_mode) != 0o700)
            ):
                raise AttemptError("private attempt staging root changed while secured")
            return parent / name, descriptor
        except (AttemptError, InventoryError, NotImplementedError, OSError) as exc:
            if descriptor >= 0:
                os.close(descriptor)
            if created is not None:
                try:
                    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    if (
                        stat.S_ISDIR(current.st_mode)
                        and (current.st_dev, current.st_ino)
                        == (created.st_dev, created.st_ino)
                    ):
                        os.rmdir(name, dir_fd=parent_fd)
                except OSError:
                    pass
            if isinstance(exc, AttemptError):
                raise
            raise AttemptError(f"cannot secure private attempt staging root: {exc}") from exc
    raise AttemptError("cannot allocate a unique private attempt staging root")


def _require_v3(public: object) -> tuple[dict, str]:
    if not isinstance(public, dict):
        raise AttemptError("benchmark public document must be an object")
    try:
        reportability = suite.benchmark_reportability(public)
    except ValueError as exc:
        raise AttemptError(str(exc)) from exc
    if reportability != suite.REPORTABILITY_PENDING_EXTERNAL_ATTESTATION:
        raise AttemptError(
            "one-shot attempts require an evaluator-created Benchmark v3 ceremony; "
            "legacy/local suites are permanently ineligible"
        )
    if public.get("schema") != suite.PUBLIC_DOCUMENT_SCHEMA_V3:
        raise AttemptError("one-shot attempts require the Benchmark v3 public schema")
    if public.get("domain") != suite.BENCHMARK_V3_DOMAIN.decode():
        raise AttemptError("one-shot attempts require the Benchmark v3 derivation domain")
    if public.get("suite_kind") != suite.HOLDOUT_SUITE_KIND:
        raise AttemptError("one-shot attempts require the holdout suite kind")
    suite_id = public.get("suite_id")
    if not isinstance(suite_id, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", suite_id) is None:
        raise AttemptError("benchmark public document is missing a valid suite_id")
    return public, suite_id


def _validated_evaluator_view(
    root: str | os.PathLike[str], *, include_private: bool
) -> tuple[Path, tuple[int, int], dict, object | None]:
    """Pin one real evaluator inode around the authoritative full suite loader."""
    try:
        resolved = Path(root).resolve(strict=True)
        descriptor = open_real_directory(resolved)
    except (TypeError, ValueError, InventoryError, OSError) as exc:
        raise AttemptError(f"invalid evaluator root: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if include_private:
            public, private_answers = suite.load_evaluator_private(os.fspath(resolved))
        else:
            public = suite.load_evaluator_public(os.fspath(resolved))
            private_answers = None
        named = resolved.lstat()
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise AttemptError("evaluator root changed around authoritative validation")
        _require_v3(public)
        return resolved, (opened.st_dev, opened.st_ino), public, private_answers
    except AttemptError:
        raise
    except (ValueError, OSError) as exc:
        raise AttemptError(f"invalid evaluator root: {exc}") from exc
    finally:
        os.close(descriptor)


def _directory_ancestry_snapshot(directory_fd: int) -> tuple[tuple[int, int], ...]:
    """Return actual ``..`` inode relationships from a held directory through its root."""
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    current = os.dup(directory_fd)
    ancestry: list[tuple[int, int]] = []
    try:
        for _depth in range(1024):
            state = os.fstat(current)
            identity = (state.st_dev, state.st_ino)
            if identity in ancestry:
                raise AttemptError("directory ancestry contains an unexpected inode cycle")
            ancestry.append(identity)
            try:
                parent = os.open("..", flags, dir_fd=current)
            except (NotImplementedError, OSError) as exc:
                raise AttemptError(f"cannot traverse held directory ancestry: {exc}") from exc
            parent_state = os.fstat(parent)
            parent_identity = (parent_state.st_dev, parent_state.st_ino)
            os.close(current)
            current = parent
            if parent_identity == identity:
                return tuple(ancestry)
        raise AttemptError("directory ancestry exceeds the 1024-component safety bound")
    finally:
        os.close(current)


def _directory_ancestry_contains(
    directory_fd: int, forbidden_identity: tuple[int, int]
) -> bool:
    """Test a held directory by inode, independent of path spelling and case aliases."""
    return forbidden_identity in _directory_ancestry_snapshot(directory_fd)


def _require_stable_ancestry(
    directory_fd: int,
    expected: tuple[tuple[int, int], ...],
    *,
    forbidden_identity: tuple[int, int],
    where: str,
) -> None:
    current = _directory_ancestry_snapshot(directory_fd)
    if forbidden_identity in current:
        raise AttemptError(f"{where} moved inside the evaluator root")
    if current != expected:
        raise AttemptError(f"{where} ancestry changed during the operation")


def _read_private_record_at(root_fd: int, name: str, where: str, *, max_bytes: int) -> bytes:
    """Read one stable ledger inode while enforcing its complete private carrier profile."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        before = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise AttemptError(f"{where} must be a regular file, not a link or special file")
        descriptor = os.open(name, flags, dir_fd=root_fd)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise AttemptError(f"{where} changed while it was being opened")
        if opened.st_size > max_bytes:
            raise AttemptError(f"{where} exceeds the {max_bytes}-byte input limit")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > max_bytes:
                raise AttemptError(f"{where} exceeds the {max_bytes}-byte input limit")
            chunks.append(chunk)
        after_read = os.fstat(descriptor)
        after_path = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except AttemptError:
        raise
    except (NotImplementedError, OSError) as exc:
        raise AttemptError(f"cannot inspect {where}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    stable = (
        "st_dev",
        "st_ino",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
        "st_nlink",
        "st_mode",
    )
    if any(
        getattr(opened, field) != getattr(after_read, field)
        or getattr(after_read, field) != getattr(after_path, field)
        for field in stable
    ):
        raise AttemptError(f"{where} changed while it was being read")
    if not stat.S_ISREG(after_read.st_mode) or after_read.st_nlink != 1:
        raise AttemptError(f"{where} must be a single-link regular file")
    if os.name != "nt" and stat.S_IMODE(after_read.st_mode) != 0o600:
        raise AttemptError(f"{where} mode must be exactly 0600")
    data = b"".join(chunks)
    if len(data) != after_read.st_size:
        raise AttemptError(f"{where} length changed while it was being read")
    return data


def accept_precommit(
    root: str | os.PathLike[str],
    evaluator_root: str | os.PathLike[str],
    data: bytes,
) -> dict:
    """Validate an evaluator root, then accept a precommit into a new designated ledger."""
    require_attempt_platform()
    _evaluator_path, evaluator_identity, public, _private_answers = _validated_evaluator_view(
        evaluator_root, include_private=False
    )
    _public, suite_id = _require_v3(public)
    try:
        precommit = parse_precommit(data, expected_suite_id=suite_id)
    except ValueError as exc:
        raise AttemptError(str(exc)) from exc

    requested = Path(root)
    if not requested.name or requested.name in {".", ".."}:
        raise AttemptError("attempt root must have one non-empty final component")
    try:
        parent = requested.parent.resolve(strict=True)
        parent_fd = open_real_directory(parent)
    except (InventoryError, OSError) as exc:
        raise AttemptError(f"attempt parent must be a real directory: {exc}") from exc
    destination = parent / requested.name
    staging: Path | None = None
    root_fd = -1
    published = successful = False
    try:
        if _directory_ancestry_contains(parent_fd, evaluator_identity):
            raise AttemptError("attempt ledger must be outside the evaluator root")
        try:
            os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except (NotImplementedError, OSError) as exc:
            raise AttemptError(f"cannot inspect attempt destination safely: {exc}") from exc
        else:
            raise AttemptError(f"refusing pre-existing attempt root: {destination}")

        staging, root_fd = _create_staging_directory(
            parent_fd, parent, destination.name
        )
        acceptance_unsigned = {
            "accepted_at": _timestamp(),
            "attempt_id": _attempt_id(),
            "precommit": {
                "commitment_id": precommit["commitment_id"],
                "sha256": _sha256(data),
                "size": len(data),
            },
            "schema": ACCEPTANCE_SCHEMA,
            "state": "precommit-accepted",
            "suite_id": suite_id,
            "trust": ATTEMPT_TRUST,
        }
        acceptance_bytes = _record_bytes(acceptance_unsigned)
        _write_exclusive_record(root_fd, LOCK_FILE, LOCK_PAYLOAD)
        _write_exclusive_record(root_fd, PRECOMMIT_FILE, data)
        _write_exclusive_record(root_fd, ACCEPTANCE_FILE, acceptance_bytes)
        if set(os.listdir(root_fd)) != {ACCEPTANCE_FILE, LOCK_FILE, PRECOMMIT_FILE}:
            raise AttemptError("new attempt root does not contain its exact initial records")
        if not directory_entry_matches_descriptor(parent_fd, staging.name, root_fd):
            raise AttemptError("attempt staging root changed before publication")
        publication_ancestry = _directory_ancestry_snapshot(parent_fd)
        if evaluator_identity in publication_ancestry:
            raise AttemptError("attempt ledger parent moved inside the evaluator root")
        state = os.fstat(root_fd)
        rename_directory_no_replace(
            staging,
            destination,
            parent_fd=parent_fd,
            expected_source=(state.st_dev, state.st_ino),
        )
        published = True
        if not directory_entry_matches_descriptor(parent_fd, destination.name, root_fd):
            raise AttemptError("published attempt root is not the verified staging inode")
        os.fsync(parent_fd)
        _require_stable_ancestry(
            parent_fd,
            publication_ancestry,
            forbidden_identity=evaluator_identity,
            where="attempt ledger parent",
        )
        if not directory_entry_matches_descriptor(parent_fd, destination.name, root_fd):
            raise AttemptError("published attempt root changed after ancestry validation")
        successful = True
        return _parse_record(
            acceptance_bytes,
            schema=ACCEPTANCE_SCHEMA,
            fields={
                "accepted_at",
                "attempt_id",
                "precommit",
                "schema",
                "state",
                "suite_id",
                "trust",
            },
            where="attempt acceptance",
        )
    except FileExistsError as exc:
        raise AttemptError(f"refusing attempt destination that appeared: {destination}") from exc
    except InventoryError as exc:
        raise AttemptError(f"cannot publish attempt root safely: {exc}") from exc
    finally:
        if root_fd >= 0 and not successful and staging is not None:
            name = destination.name if published else staging.name
            remove_pinned_directory_at(parent_fd, name, root_fd)
        if root_fd >= 0:
            os.close(root_fd)
        os.close(parent_fd)


_ACCEPTANCE_FIELDS = {
    "accepted_at",
    "attempt_id",
    "precommit",
    "schema",
    "state",
    "suite_id",
    "trust",
}
_CLAIM_FIELDS = {
    "attempt_id",
    "claimed_at",
    "expected_submission",
    "previous",
    "schema",
    "state",
    "suite_id",
}
_RESULT_FIELDS = {
    "attempt_id",
    "detail",
    "outcome",
    "previous",
    "schema",
    "blinding_nonce",
    "suite_id",
}
_RECEIPT_FIELDS = {
    "attempt_id",
    "notice",
    "previous",
    "schema",
    "state",
    "suite_id",
}
_RETIREMENT_FIELDS = {
    "attempt_id",
    "previous",
    "retired_at",
    "schema",
    "state",
    "suite_id",
    "trust",
}


def _require_private_root(root_fd: int) -> None:
    state = os.fstat(root_fd)
    if not stat.S_ISDIR(state.st_mode):  # pragma: no cover - open_real_directory invariant
        raise AttemptError("attempt root must be a directory")
    if os.name != "nt" and stat.S_IMODE(state.st_mode) != 0o700:
        raise AttemptError("attempt root mode must be exactly 0700")


def _load_acceptance_pair(
    root_fd: int, *, expected_suite_id: str | None = None
) -> tuple[dict, bytes, dict, bytes]:
    acceptance_bytes = _read_private_record_at(
        root_fd,
        ACCEPTANCE_FILE,
        "attempt acceptance",
        max_bytes=MAX_LEDGER_RECORD_BYTES,
    )
    precommit_bytes = _read_private_record_at(
        root_fd,
        PRECOMMIT_FILE,
        "attempt precommitment",
        max_bytes=MAX_PRECOMMIT_BYTES,
    )
    acceptance = _parse_record(
        acceptance_bytes,
        schema=ACCEPTANCE_SCHEMA,
        fields=_ACCEPTANCE_FIELDS,
        where="attempt acceptance",
    )
    suite_id = acceptance.get("suite_id")
    if not isinstance(suite_id, str) or _SHA256.fullmatch(suite_id) is None:
        raise AttemptError("attempt acceptance suite_id is invalid")
    if expected_suite_id is not None and suite_id != expected_suite_id:
        raise AttemptError("attempt acceptance suite_id does not match evaluator suite")
    try:
        precommit = parse_precommit(precommit_bytes, expected_suite_id=suite_id)
    except ValueError as exc:
        raise AttemptError(str(exc)) from exc
    if (
        not isinstance(acceptance["attempt_id"], str)
        or _ATTEMPT_ID.fullmatch(acceptance["attempt_id"]) is None
    ):
        raise AttemptError("attempt acceptance attempt_id is invalid")
    _require_timestamp(acceptance["accepted_at"], "attempt acceptance")
    if acceptance["state"] != "precommit-accepted" or acceptance["trust"] != ATTEMPT_TRUST:
        raise AttemptError("attempt acceptance state/trust contract is invalid")
    if acceptance["precommit"] != {
        "commitment_id": precommit["commitment_id"],
        "sha256": _sha256(precommit_bytes),
        "size": len(precommit_bytes),
    }:
        raise AttemptError("attempt acceptance does not bind the stored precommitment")
    return acceptance, acceptance_bytes, precommit, precommit_bytes


def _open_ledger_root(root: str | os.PathLike[str]) -> int:
    try:
        root_fd = open_real_directory(root)
    except (InventoryError, OSError) as exc:
        raise AttemptError(f"attempt root must be a real directory: {exc}") from exc
    try:
        _require_private_root(root_fd)
        return root_fd
    except Exception:
        os.close(root_fd)
        raise


_INITIAL_FILES = {ACCEPTANCE_FILE, PRECOMMIT_FILE, LOCK_FILE}
_LIVE_PREFIXES = (
    _INITIAL_FILES,
    _INITIAL_FILES | {CLAIM_FILE},
    _INITIAL_FILES | {CLAIM_FILE, RESULT_FILE},
    _INITIAL_FILES | {CLAIM_FILE, RESULT_FILE, RECEIPT_FILE},
)


def _load_unclaimed_ledger(
    root_fd: int, *, expected_suite_id: str
) -> tuple[dict, bytes, dict]:
    names = set(os.listdir(root_fd))
    if RETIREMENT_FILE in names:
        raise AttemptConsumedError("attempt is already retired")
    if names != _INITIAL_FILES:
        if CLAIM_FILE in names or RESULT_FILE in names or RECEIPT_FILE in names:
            raise AttemptConsumedError(
                "attempt claim already exists or later one-shot state is present"
            )
        raise AttemptError("unclaimed attempt root has missing or unexpected records")
    acceptance, acceptance_bytes, precommit, _precommit_bytes = _load_acceptance_pair(
        root_fd, expected_suite_id=expected_suite_id
    )
    return acceptance, acceptance_bytes, precommit


def _read_reveal(
    path: str | os.PathLike[str],
    *,
    forbidden_identity: tuple[int, int],
) -> bytes:
    reveal = Path(path)
    if not reveal.name or reveal.name in {".", ".."}:
        raise _RevealRejected("unreadable-reveal")
    try:
        parent = reveal.parent.resolve(strict=True)
        parent_fd = open_real_directory(parent)
    except (InventoryError, OSError) as exc:
        raise _RevealRejected("unreadable-reveal") from exc
    try:
        before = _directory_ancestry_snapshot(parent_fd)
        if forbidden_identity in before:
            raise _RevealRejected("forbidden-reveal-location")
        data = suite._read_regular_at(
            parent_fd,
            reveal.name,
            "benchmark reveal",
            max_bytes=MAX_SUBMISSION_BYTES,
        )
        after = _directory_ancestry_snapshot(parent_fd)
        if forbidden_identity in after:
            raise _RevealRejected("forbidden-reveal-location")
        if after != before:
            raise _RevealRejected("unreadable-reveal")
        return data
    except ValueError as exc:
        raise _RevealRejected("unreadable-reveal") from exc
    except AttemptError as exc:
        raise _RevealRejected("unreadable-reveal") from exc
    finally:
        os.close(parent_fd)


def _score_reveal(public: dict, private_answers: object, reveal: bytes, precommit: dict) -> dict:
    if len(reveal) != precommit["submission"]["size"] or _sha256(reveal) != precommit[
        "submission"
    ]["sha256"]:
        raise _RevealRejected("reveal-binding-mismatch")
    try:
        parsed = parse_submission(reveal, public)
    except ValueError as exc:
        raise _RevealRejected("invalid-canonical-reveal") from exc
    if not isinstance(private_answers, dict):
        raise AttemptError("evaluator private answers must be keyed by scenario_id")
    per_kind: dict[str, dict[str, int]] = {}
    scenario_results: list[dict] = []
    correct = total = 0
    for scenario in public["scenarios"]:
        scenario_id = scenario["scenario_id"]
        private = private_answers.get(scenario_id)
        if not isinstance(private, dict) or not isinstance(private.get("answers"), dict):
            raise AttemptError(f"evaluator private answers are missing {scenario_id!r}")
        submitted = parsed.answers[scenario_id]
        question_results: dict[str, bool] = {}
        scenario_correct = 0
        for question in scenario["questions"]:
            question_id = question["id"]
            expected = private["answers"].get(question_id)
            if not isinstance(expected, str):
                raise AttemptError(
                    f"evaluator private answer {scenario_id!r}/{question_id!r} is invalid"
                )
            ok = normalize(submitted[question_id], question["kind"]) == normalize(
                expected, question["kind"]
            )
            question_results[question_id] = ok
            scenario_correct += int(ok)
            correct += int(ok)
            total += 1
            counts = per_kind.setdefault(question["kind"], {"correct": 0, "total": 0})
            counts["correct"] += int(ok)
            counts["total"] += 1
        scenario_results.append(
            {
                "correct": scenario_correct,
                "questions": question_results,
                "scenario_id": scenario_id,
                "total": len(scenario["questions"]),
            }
        )
    return {
        "correct": correct,
        "per_kind": {name: per_kind[name] for name in sorted(per_kind)},
        "scenarios": scenario_results,
        "total": total,
    }


def _require_count(value: object, where: str, *, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise AttemptError(f"{where} is invalid")
    return value


def _validate_scored_detail(detail: object) -> None:
    if not isinstance(detail, dict) or set(detail) != {
        "correct",
        "per_kind",
        "scenarios",
        "total",
    }:
        raise AttemptError("scored attempt detail has unknown or missing fields")
    maximum_total = suite.BENCHMARK_MAX_SCENARIOS * suite.BENCHMARK_QUESTIONS_PER_SCENE
    total = _require_count(detail["total"], "scored attempt total", maximum=maximum_total)
    correct = _require_count(
        detail["correct"], "scored attempt correct count", maximum=maximum_total
    )
    if (
        correct > total
        or total < suite.BENCHMARK_V3_MIN_SCENARIOS * suite.BENCHMARK_QUESTIONS_PER_SCENE
        or total % suite.BENCHMARK_QUESTIONS_PER_SCENE
    ):
        raise AttemptError("scored attempt aggregate is outside the Benchmark v3 contract")
    scenarios = detail["scenarios"]
    if not isinstance(scenarios, list) or len(scenarios) != total // suite.BENCHMARK_QUESTIONS_PER_SCENE:
        raise AttemptError("scored attempt scenario aggregate is invalid")
    seen: set[str] = set()
    scenario_correct = scenario_total = 0
    for index, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict) or set(scenario) != {
            "correct",
            "questions",
            "scenario_id",
            "total",
        }:
            raise AttemptError(f"scored attempt scenario {index} is invalid")
        scenario_id = scenario["scenario_id"]
        if (
            not isinstance(scenario_id, str)
            or _SCENARIO_ID.fullmatch(scenario_id) is None
            or scenario_id in seen
        ):
            raise AttemptError(f"scored attempt scenario {index} identity is invalid")
        seen.add(scenario_id)
        questions = scenario["questions"]
        if (
            not isinstance(questions, dict)
            or len(questions) != suite.BENCHMARK_QUESTIONS_PER_SCENE
            or not all(
                isinstance(question_id, str)
                and bool(question_id)
                and type(value) is bool
                for question_id, value in questions.items()
            )
        ):
            raise AttemptError(f"scored attempt scenario {scenario_id!r} questions are invalid")
        row_total = _require_count(
            scenario["total"],
            f"scored attempt scenario {scenario_id!r} total",
            maximum=suite.BENCHMARK_QUESTIONS_PER_SCENE,
        )
        row_correct = _require_count(
            scenario["correct"],
            f"scored attempt scenario {scenario_id!r} correct count",
            maximum=suite.BENCHMARK_QUESTIONS_PER_SCENE,
        )
        if (
            row_total != suite.BENCHMARK_QUESTIONS_PER_SCENE
            or row_correct != sum(questions.values())
        ):
            raise AttemptError(f"scored attempt scenario {scenario_id!r} counts are invalid")
        scenario_total += row_total
        scenario_correct += row_correct
    per_kind = detail["per_kind"]
    if not isinstance(per_kind, dict) or not per_kind:
        raise AttemptError("scored attempt per-kind aggregate is invalid")
    kind_total = kind_correct = 0
    for kind, counts in per_kind.items():
        if (
            not isinstance(kind, str)
            or not kind
            or not isinstance(counts, dict)
            or set(counts) != {"correct", "total"}
        ):
            raise AttemptError("scored attempt per-kind row is invalid")
        current_total = _require_count(
            counts["total"], f"scored attempt kind {kind!r} total", maximum=maximum_total
        )
        current_correct = _require_count(
            counts["correct"],
            f"scored attempt kind {kind!r} correct count",
            maximum=maximum_total,
        )
        if current_correct > current_total or current_total == 0:
            raise AttemptError(f"scored attempt kind {kind!r} counts are invalid")
        kind_total += current_total
        kind_correct += current_correct
    if (scenario_correct, scenario_total) != (correct, total) or (
        kind_correct,
        kind_total,
    ) != (correct, total):
        raise AttemptError("scored attempt detail aggregates disagree")


def _validate_live_record(
    name: str,
    record: dict,
    *,
    acceptance: dict,
    precommit: dict,
) -> None:
    if record["attempt_id"] != acceptance["attempt_id"] or record["suite_id"] != acceptance[
        "suite_id"
    ]:
        raise AttemptError(f"attempt {name} crosses attempt or suite identity")
    if name == CLAIM_FILE:
        _require_timestamp(record["claimed_at"], "attempt claim")
        if record["claimed_at"] < acceptance["accepted_at"]:
            raise AttemptError("attempt claim predates acceptance")
        if (
            record["state"] != "reveal-claimed"
            or record["expected_submission"] != precommit["submission"]
        ):
            raise AttemptError("attempt claim state/submission contract is invalid")
        return
    if name == RESULT_FILE:
        if not isinstance(record["blinding_nonce"], str) or _SHA256.fullmatch(
            record["blinding_nonce"]
        ) is None:
            raise AttemptError("attempt result blinding_nonce is invalid")
        if record["outcome"] == "scored":
            _validate_scored_detail(record["detail"])
        elif record["outcome"] == "rejected":
            allowed_reasons = {
                "forbidden-reveal-location",
                "invalid-canonical-reveal",
                "reveal-binding-mismatch",
                "unreadable-reveal",
            }
            if (
                not isinstance(record["detail"], dict)
                or set(record["detail"]) != {"reason"}
                or record["detail"]["reason"] not in allowed_reasons
            ):
                raise AttemptError("rejected attempt detail is invalid")
        else:
            raise AttemptError("attempt result outcome is invalid")
        return
    if name == RECEIPT_FILE and (
        record["notice"] != WITHHELD_RECEIPT_NOTICE
        or record["state"] != "consumed-feedback-withheld"
    ):
        raise AttemptError("attempt receipt state/notice contract is invalid")


def _require_live_inventory(names: set[str], *, retired: bool | None) -> set[str]:
    has_retirement = RETIREMENT_FILE in names
    if retired is True and not has_retirement:
        raise AttemptNotRetiredError("detailed attempt feedback is withheld until retirement")
    if retired is False and has_retirement:
        raise AttemptConsumedError("attempt is already retired")
    live = names - {RETIREMENT_FILE}
    if live not in _LIVE_PREFIXES:
        raise AttemptError("attempt root has missing, out-of-order or unexpected records")
    return live


def _load_live_chain(
    root_fd: int,
    names: set[str],
    *,
    expected_suite_id: str | None = None,
) -> tuple[dict, bytes, dict, list[tuple[str, bytes, dict]]]:
    acceptance, acceptance_bytes, precommit, _precommit_bytes = _load_acceptance_pair(
        root_fd, expected_suite_id=expected_suite_id
    )
    chain: list[tuple[str, bytes, dict]] = [
        (ACCEPTANCE_FILE, acceptance_bytes, acceptance)
    ]
    previous_name = ACCEPTANCE_FILE
    previous_bytes = acceptance_bytes
    validators = (
        (CLAIM_FILE, CLAIM_SCHEMA, _CLAIM_FIELDS),
        (RESULT_FILE, RESULT_SCHEMA, _RESULT_FIELDS),
        (RECEIPT_FILE, RECEIPT_SCHEMA, _RECEIPT_FIELDS),
    )
    for name, schema, fields in validators:
        if name not in names:
            continue
        data = _read_private_record_at(
            root_fd, name, f"attempt {name}", max_bytes=MAX_LEDGER_RECORD_BYTES
        )
        record = _parse_record(data, schema=schema, fields=fields, where=f"attempt {name}")
        _validate_live_record(
            name,
            record,
            acceptance=acceptance,
            precommit=precommit,
        )
        if record["previous"] != {
            "file": previous_name,
            "sha256": _sha256(previous_bytes),
        }:
            raise AttemptError(f"attempt {name} breaks the hash-linked record chain")
        chain.append((name, data, record))
        previous_name, previous_bytes = name, data
    return acceptance, acceptance_bytes, precommit, chain


def consume_attempt(
    root: str | os.PathLike[str],
    evaluator_root: str | os.PathLike[str],
    reveal_path: str | os.PathLike[str],
) -> dict:
    """Claim once, then read/grade the reveal and return only an opaque receipt."""
    require_attempt_platform()
    _evaluator_path, evaluator_identity, public, private_answers = _validated_evaluator_view(
        evaluator_root, include_private=True
    )
    _public, suite_id = _require_v3(public)
    root_fd = _open_ledger_root(root)
    try:
        with _operation_lock(root_fd):
            ledger_ancestry = _directory_ancestry_snapshot(root_fd)
            if evaluator_identity in ledger_ancestry:
                raise AttemptError("attempt ledger must be outside the evaluator root")
            acceptance, acceptance_bytes, precommit = _load_unclaimed_ledger(
                root_fd, expected_suite_id=suite_id
            )
            claimed_at = _transition_timestamp(
                not_before=acceptance["accepted_at"], transition="attempt claim"
            )
            claim_unsigned = {
                "attempt_id": acceptance["attempt_id"],
                "claimed_at": claimed_at,
                "expected_submission": dict(precommit["submission"]),
                "previous": {
                    "file": ACCEPTANCE_FILE,
                    "sha256": _sha256(acceptance_bytes),
                },
                "schema": CLAIM_SCHEMA,
                "state": "reveal-claimed",
                "suite_id": acceptance["suite_id"],
            }
            claim_bytes = _record_bytes(claim_unsigned)
            try:
                _publish_atomic_record(root_fd, CLAIM_FILE, claim_bytes)
            except FileExistsError as exc:
                raise AttemptConsumedError("attempt reveal was already claimed") from exc
            _require_stable_ancestry(
                root_fd,
                ledger_ancestry,
                forbidden_identity=evaluator_identity,
                where="attempt ledger",
            )

            try:
                reveal = _read_reveal(
                    reveal_path,
                    forbidden_identity=evaluator_identity,
                )
                detail = _score_reveal(public, private_answers, reveal, precommit)
                outcome = "scored"
            except _RevealRejected as exc:
                detail = {"reason": exc.code}
                outcome = "rejected"

            result_unsigned = {
                "attempt_id": acceptance["attempt_id"],
                "detail": detail,
                "outcome": outcome,
                "previous": {"file": CLAIM_FILE, "sha256": _sha256(claim_bytes)},
                "schema": RESULT_SCHEMA,
                # This random value makes the result hash computationally hiding from the
                # receipt recipient. It is not encryption: the ledger owner can read detail.
                "blinding_nonce": "sha256:" + secrets.token_hex(32),
                "suite_id": acceptance["suite_id"],
            }
            result_bytes = _record_bytes(result_unsigned)
            _publish_atomic_record(root_fd, RESULT_FILE, result_bytes)
            _require_stable_ancestry(
                root_fd,
                ledger_ancestry,
                forbidden_identity=evaluator_identity,
                where="attempt ledger",
            )
            receipt_unsigned = {
                "attempt_id": acceptance["attempt_id"],
                "notice": WITHHELD_RECEIPT_NOTICE,
                "previous": {"file": RESULT_FILE, "sha256": _sha256(result_bytes)},
                "schema": RECEIPT_SCHEMA,
                "state": "consumed-feedback-withheld",
                "suite_id": acceptance["suite_id"],
            }
            receipt_bytes = _record_bytes(receipt_unsigned)
            _publish_atomic_record(root_fd, RECEIPT_FILE, receipt_bytes)
            _require_stable_ancestry(
                root_fd,
                ledger_ancestry,
                forbidden_identity=evaluator_identity,
                where="attempt ledger",
            )
            return _parse_record(
                receipt_bytes,
                schema=RECEIPT_SCHEMA,
                fields=_RECEIPT_FIELDS,
                where="attempt receipt",
            )
    finally:
        os.close(root_fd)


def retire_attempt(root: str | os.PathLike[str]) -> dict:
    """Retire local-ledger state, including an unclaimed or crash-bricked attempt."""
    require_attempt_platform()
    root_fd = _open_ledger_root(root)
    try:
        with _operation_lock(root_fd):
            names = set(os.listdir(root_fd))
            live_names = _require_live_inventory(names, retired=False)
            acceptance, _acceptance_bytes, _precommit, chain = _load_live_chain(
                root_fd, live_names
            )
            latest_name, latest_bytes, _latest_record = chain[-1]
            claim = next(
                (record for name, _data, record in chain if name == CLAIM_FILE), None
            )
            chronological_floor = (
                claim["claimed_at"] if claim is not None else acceptance["accepted_at"]
            )
            retired_at = _transition_timestamp(
                not_before=chronological_floor, transition="attempt retirement"
            )
            retirement_unsigned = {
                "attempt_id": acceptance["attempt_id"],
                "previous": {"file": latest_name, "sha256": _sha256(latest_bytes)},
                "retired_at": retired_at,
                "schema": RETIREMENT_SCHEMA,
                "state": "retired-feedback-releasable",
                "suite_id": acceptance["suite_id"],
                "trust": ATTEMPT_TRUST,
            }
            retirement_bytes = _record_bytes(retirement_unsigned)
            try:
                _publish_atomic_record(root_fd, RETIREMENT_FILE, retirement_bytes)
            except FileExistsError as exc:
                raise AttemptConsumedError("attempt was concurrently retired") from exc
            return _parse_record(
                retirement_bytes,
                schema=RETIREMENT_SCHEMA,
                fields=_RETIREMENT_FIELDS,
                where="attempt retirement",
            )
    finally:
        os.close(root_fd)


def retired_report(root: str | os.PathLike[str]) -> dict:
    """Return a self-bound evidence bundle only after validating terminal retirement."""
    require_attempt_platform()
    root_fd = _open_ledger_root(root)
    try:
        with _operation_lock(root_fd):
            names = set(os.listdir(root_fd))
            live_names = _require_live_inventory(names, retired=True)
            acceptance, _acceptance_bytes, precommit, chain = _load_live_chain(
                root_fd, live_names
            )
            retirement_bytes = _read_private_record_at(
                root_fd,
                RETIREMENT_FILE,
                "attempt retirement",
                max_bytes=MAX_LEDGER_RECORD_BYTES,
            )
            retirement = _parse_record(
                retirement_bytes,
                schema=RETIREMENT_SCHEMA,
                fields=_RETIREMENT_FIELDS,
                where="attempt retirement",
            )
            if retirement["attempt_id"] != acceptance["attempt_id"] or retirement[
                "suite_id"
            ] != acceptance["suite_id"]:
                raise AttemptError("attempt retirement crosses attempt or suite identity")
            _require_timestamp(retirement["retired_at"], "attempt retirement")
            by_name = {name: record for name, _data, record in chain}
            chronological_floor = (
                by_name[CLAIM_FILE]["claimed_at"]
                if CLAIM_FILE in by_name
                else acceptance["accepted_at"]
            )
            if (
                retirement["retired_at"] < chronological_floor
                or retirement["state"] != "retired-feedback-releasable"
                or retirement["trust"] != ATTEMPT_TRUST
            ):
                raise AttemptError("attempt retirement state/trust contract is invalid")
            previous_name, previous_bytes, _previous_record = chain[-1]
            if retirement["previous"] != {
                "file": previous_name,
                "sha256": _sha256(previous_bytes),
            }:
                raise AttemptError("attempt retirement does not terminate the latest record")
            result = by_name.get(RESULT_FILE)
            if result is None:
                detail = {"reason": "no-private-result"}
                outcome = "retired-without-result"
            else:
                detail = result["detail"]
                outcome = result["outcome"]
            evidence = {
                "acceptance": acceptance,
                "claim": by_name.get(CLAIM_FILE),
                "precommit": precommit,
                "receipt": by_name.get(RECEIPT_FILE),
                "result": result,
                "retirement": retirement,
                "reveal_commitment": dict(precommit["submission"]),
            }
            unsigned_report = {
                "attempt_id": acceptance["attempt_id"],
                "detail": detail,
                "evidence": evidence,
                "notice": RETIRED_REPORT_NOTICE,
                "outcome": outcome,
                "reportability": suite.REPORTABILITY_PENDING_EXTERNAL_ATTESTATION,
                "reportable": False,
                "retirement_record_id": retirement["record_id"],
                "schema": REPORT_SCHEMA,
                "suite_id": acceptance["suite_id"],
                "trust": ATTEMPT_TRUST,
            }
            return {
                **unsigned_report,
                "report_id": _sha256(suite.canonical_public_bytes(unsigned_report)),
            }
    finally:
        os.close(root_fd)


_REPORT_FIELDS = {
    "attempt_id",
    "detail",
    "evidence",
    "notice",
    "outcome",
    "report_id",
    "reportability",
    "reportable",
    "retirement_record_id",
    "schema",
    "suite_id",
    "trust",
}
_EVIDENCE_FIELDS = {
    "acceptance",
    "claim",
    "precommit",
    "receipt",
    "result",
    "retirement",
    "reveal_commitment",
}


def _record_object_bytes(
    value: object, *, schema: str, fields: set[str], where: str
) -> tuple[bytes, dict]:
    if not isinstance(value, dict):
        raise AttemptError(f"{where} must be an object")
    try:
        data = suite.canonical_public_bytes(value)
    except ValueError as exc:
        raise AttemptError(f"{where} is invalid: {exc}") from exc
    return data, _parse_record(data, schema=schema, fields=fields, where=where)


def verify_retired_report(document: object, *, reveal: bytes | None = None) -> dict:
    """Verify a detached retired evidence bundle and optionally its exact reveal digest.

    This verifies the canonical self-hash, internally checkable record semantics,
    precommit/reveal binding, and complete hash-linked opening from acceptance through
    retirement. It neither authenticates the ceremony origin nor proves that scenario IDs,
    question IDs, answers or grading agree with an evaluator suite. It does not turn the local
    self-attestation into an external witness.
    """
    if not isinstance(document, dict) or set(document) != _REPORT_FIELDS:
        raise AttemptError("retired report has unknown or missing fields")
    unsigned = dict(document)
    report_id = unsigned.pop("report_id")
    try:
        expected_report_id = _sha256(suite.canonical_public_bytes(unsigned))
    except ValueError as exc:
        raise AttemptError(f"retired report is not canonical public data: {exc}") from exc
    if not isinstance(report_id, str) or report_id != expected_report_id:
        raise AttemptError("retired report_id does not bind its evidence bundle")
    if (
        document["schema"] != REPORT_SCHEMA
        or document["reportable"] is not False
        or document["reportability"]
        != suite.REPORTABILITY_PENDING_EXTERNAL_ATTESTATION
        or document["notice"] != RETIRED_REPORT_NOTICE
        or document["trust"] != ATTEMPT_TRUST
    ):
        raise AttemptError("retired reportability/trust contract is invalid")
    suite_id = document["suite_id"]
    attempt_id = document["attempt_id"]
    if not isinstance(suite_id, str) or _SHA256.fullmatch(suite_id) is None:
        raise AttemptError("retired report suite_id is invalid")
    if not isinstance(attempt_id, str) or _ATTEMPT_ID.fullmatch(attempt_id) is None:
        raise AttemptError("retired report attempt_id is invalid")
    evidence = document["evidence"]
    if not isinstance(evidence, dict) or set(evidence) != _EVIDENCE_FIELDS:
        raise AttemptError("retired report evidence has unknown or missing fields")

    acceptance_bytes, acceptance = _record_object_bytes(
        evidence["acceptance"],
        schema=ACCEPTANCE_SCHEMA,
        fields=_ACCEPTANCE_FIELDS,
        where="retired evidence acceptance",
    )
    if acceptance["suite_id"] != suite_id or acceptance["attempt_id"] != attempt_id:
        raise AttemptError("retired evidence acceptance crosses report identity")
    _require_timestamp(acceptance["accepted_at"], "retired evidence acceptance")
    if acceptance["state"] != "precommit-accepted" or acceptance["trust"] != ATTEMPT_TRUST:
        raise AttemptError("retired evidence acceptance state/trust contract is invalid")
    precommit_value = evidence["precommit"]
    if not isinstance(precommit_value, dict):
        raise AttemptError("retired evidence precommit must be an object")
    try:
        precommit_bytes = suite.canonical_public_bytes(precommit_value)
        precommit = parse_precommit(precommit_bytes, expected_suite_id=suite_id)
    except ValueError as exc:
        raise AttemptError(f"retired evidence precommit is invalid: {exc}") from exc
    if acceptance["precommit"] != {
        "commitment_id": precommit["commitment_id"],
        "sha256": _sha256(precommit_bytes),
        "size": len(precommit_bytes),
    }:
        raise AttemptError("retired evidence acceptance does not bind its precommit")
    if evidence["reveal_commitment"] != precommit["submission"]:
        raise AttemptError("retired evidence reveal commitment disagrees with precommit")

    chain: list[tuple[str, bytes, dict]] = [
        (ACCEPTANCE_FILE, acceptance_bytes, acceptance)
    ]
    specifications = (
        ("claim", CLAIM_FILE, CLAIM_SCHEMA, _CLAIM_FIELDS),
        ("result", RESULT_FILE, RESULT_SCHEMA, _RESULT_FIELDS),
        ("receipt", RECEIPT_FILE, RECEIPT_SCHEMA, _RECEIPT_FIELDS),
    )
    missing_seen = False
    for evidence_name, filename, schema, fields in specifications:
        value = evidence[evidence_name]
        if value is None:
            missing_seen = True
            continue
        if missing_seen:
            raise AttemptError("retired evidence live records are not a complete prefix")
        data, record = _record_object_bytes(
            value,
            schema=schema,
            fields=fields,
            where=f"retired evidence {evidence_name}",
        )
        _validate_live_record(
            filename,
            record,
            acceptance=acceptance,
            precommit=precommit,
        )
        previous_name, previous_bytes, _previous_record = chain[-1]
        if record["previous"] != {
            "file": previous_name,
            "sha256": _sha256(previous_bytes),
        }:
            raise AttemptError(f"retired evidence {evidence_name} breaks the record chain")
        chain.append((filename, data, record))

    retirement_bytes, retirement = _record_object_bytes(
        evidence["retirement"],
        schema=RETIREMENT_SCHEMA,
        fields=_RETIREMENT_FIELDS,
        where="retired evidence retirement",
    )
    if retirement["suite_id"] != suite_id or retirement["attempt_id"] != attempt_id:
        raise AttemptError("retired evidence retirement crosses report identity")
    _require_timestamp(retirement["retired_at"], "retired evidence retirement")
    claim = next((record for name, _data, record in chain if name == CLAIM_FILE), None)
    chronological_floor = (
        claim["claimed_at"] if claim is not None else acceptance["accepted_at"]
    )
    if (
        retirement["retired_at"] < chronological_floor
        or retirement["state"] != "retired-feedback-releasable"
        or retirement["trust"] != ATTEMPT_TRUST
    ):
        raise AttemptError("retired evidence retirement state/trust contract is invalid")
    previous_name, previous_bytes, _previous_record = chain[-1]
    if retirement["previous"] != {
        "file": previous_name,
        "sha256": _sha256(previous_bytes),
    }:
        raise AttemptError("retired evidence retirement does not terminate the record chain")
    if document["retirement_record_id"] != retirement["record_id"]:
        raise AttemptError("retired report does not identify its retirement record")

    result = next((record for name, _data, record in chain if name == RESULT_FILE), None)
    expected_outcome = "retired-without-result" if result is None else result["outcome"]
    expected_detail = {"reason": "no-private-result"} if result is None else result["detail"]
    if document["outcome"] != expected_outcome or document["detail"] != expected_detail:
        raise AttemptError("retired report disclosure does not match its opened result")
    reveal_verified = False
    if reveal is not None:
        if type(reveal) is not bytes:
            raise AttemptError("detached reveal must be immutable bytes")
        if len(reveal) != precommit["submission"]["size"] or _sha256(reveal) != precommit[
            "submission"
        ]["sha256"]:
            raise AttemptError("detached reveal does not match the retired commitment")
        reveal_verified = True
    return {
        "attempt_id": attempt_id,
        "chain_records": len(chain) + 1,
        "report_id": report_id,
        "reveal_verified": reveal_verified,
        "suite_id": suite_id,
    }


__all__ = [
    "ATTEMPT_TRUST",
    "ATTEMPT_PLATFORM_NOTICE",
    "ATTEMPT_PLATFORM_SUPPORTED",
    "AttemptBusyError",
    "AttemptConsumedError",
    "AttemptError",
    "AttemptNotRetiredError",
    "AttemptPlatformError",
    "WITHHELD_RECEIPT_NOTICE",
    "RETIRED_REPORT_NOTICE",
    "accept_precommit",
    "consume_attempt",
    "retire_attempt",
    "retired_report",
    "require_attempt_platform",
    "verify_retired_report",
]
