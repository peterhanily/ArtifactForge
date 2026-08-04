# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""CI code and its bootstrap are immutable, allowlisted, and updateable by review."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
import json
from os import stat_result
from pathlib import Path, PurePosixPath
import re
import stat

import pytest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
ACTIONS = ROOT / ".github" / "actions"

ALLOWED_ACTIONS = {
    "actions/attest": ("508db95dd578ae2727ebd6217d5ba78e4fbda05d", "v4.2.1"),
    "actions/checkout": ("de0fac2e4500dabe0009e67214ff5f5447ce83dd", "v6.0.2"),
    "actions/download-artifact": (
        "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "v8.0.1",
    ),
    "actions/upload-artifact": (
        "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "v7.0.1",
    ),
}

UV_HASHES = {
    "9da839e5a491c9a701d7d327a199cafc76ac27a03ac84fd2a8d4bf32c3af2448",
    "58c07ffc272c847d29cd98ca5082fa4304a645f87c718ec900e3cca9026bd096",
    "44ec1fe3af839f87370dcf0400c0cab917cc1ce697d563e860fc7d9ed72655e7",
}

MAX_AUTOMATION_BYTES = 2 * 1024 * 1024
MAX_AUTOMATION_NODES = 100_000
MAX_AUTOMATION_DEPTH = 64
_EXTERNAL_USE = re.compile(r"(?P<action>[^@\s]+)@(?P<commit>[0-9a-f]{40})")
_BLOCK_HEADER = re.compile(r"[|>](?:[+-]?[1-9]?|[1-9]?[+-]?)")


@dataclass(frozen=True)
class _Scalar:
    value: object
    line: int


@dataclass(frozen=True)
class _Line:
    indent: int
    content: str
    raw: str
    number: int
    block_scalar: str | None = None


def _strip_yaml_comment(value: str) -> str:
    single = False
    double = False
    escaped = False
    index = 0
    while index < len(value):
        character = value[index]
        if double:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                double = False
            index += 1
            continue
        if single:
            if character == "'":
                if index + 1 < len(value) and value[index + 1] == "'":
                    index += 2
                    continue
                single = False
            index += 1
            continue
        if character == '"':
            double = True
        elif character == "'":
            single = True
        elif character == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
        index += 1
    assert not single and not double and not escaped, "unterminated YAML quote"
    return value.rstrip()


def _mapping_separator(value: str) -> int | None:
    single = False
    double = False
    escaped = False
    flow_depth = 0
    index = 0
    while index < len(value):
        character = value[index]
        if double:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                double = False
            index += 1
            continue
        if single:
            if character == "'":
                if index + 1 < len(value) and value[index + 1] == "'":
                    index += 2
                    continue
                single = False
            index += 1
            continue
        if character == '"':
            double = True
        elif character == "'":
            single = True
        elif character in "[{":
            flow_depth += 1
        elif character in "]}":
            flow_depth -= 1
            assert flow_depth >= 0, "unbalanced YAML flow collection"
        elif (
            character == ":"
            and flow_depth == 0
            and (index + 1 == len(value) or value[index + 1].isspace())
        ):
            return index
        index += 1
    assert not single and not double and not escaped, "unterminated YAML quote"
    assert flow_depth == 0, "multiline YAML flow collections are forbidden"
    return None


def _logical_lines(source: str) -> tuple[_Line, ...]:
    physical = source.splitlines()
    result: list[_Line] = []
    index = 0
    while index < len(physical):
        line_number = index
        raw = physical[index]
        leading = raw[: len(raw) - len(raw.lstrip(" \t"))]
        assert "\t" not in leading, f"tab indentation is forbidden at line {index + 1}"
        indent = len(leading)
        content = _strip_yaml_comment(raw[indent:])
        if not content:
            index += 1
            continue
        assert content not in {"---", "..."} and not content.startswith("%"), (
            f"YAML directives/documents are forbidden at line {index + 1}"
        )
        candidate = content[1:].lstrip() if content == "-" or content.startswith("- ") else content
        separator = _mapping_separator(candidate)
        block_scalar = None
        if separator is not None and _BLOCK_HEADER.fullmatch(candidate[separator + 1 :].strip()):
            body: list[str] = []
            cursor = index + 1
            while cursor < len(physical):
                following = physical[cursor]
                if not following.strip():
                    body.append("")
                    cursor += 1
                    continue
                following_indent = len(following) - len(following.lstrip(" \t"))
                assert "\t" not in following[:following_indent], (
                    f"tab indentation is forbidden at line {cursor + 1}"
                )
                if following_indent <= indent:
                    break
                body.append(following)
                cursor += 1
            block_scalar = "\n".join(body)
            index = cursor
        else:
            index += 1
        result.append(
            _Line(
                indent=indent,
                content=content,
                raw=raw,
                number=line_number,
                block_scalar=block_scalar,
            )
        )
    return tuple(result)


def _plain_scalar(value: str, line: int) -> _Scalar:
    value = value.strip()
    assert value, f"empty scalar at line {line + 1}"
    assert not value.startswith(("&", "*", "!")) and value != "<<", (
        f"YAML anchors, aliases, tags and merge keys are forbidden at line {line + 1}"
    )
    lowered = value.lower()
    if lowered == "true":
        return _Scalar(True, line)
    if lowered == "false":
        return _Scalar(False, line)
    if lowered in {"null", "~"}:
        return _Scalar(None, line)
    # YAML 1.2 deliberately keeps `on`, `off`, `yes`, and `no` as strings.
    return _Scalar(value, line)


class _FlowParser:
    def __init__(self, source: str, line: int):
        self.source = source
        self.line = line
        self.position = 0

    def parse(self) -> object:
        result = self._value(depth=0)
        self._space()
        assert self.position == len(self.source), f"trailing flow YAML at line {self.line + 1}"
        return result

    def _space(self) -> None:
        while self.position < len(self.source) and self.source[self.position].isspace():
            self.position += 1

    def _value(self, *, depth: int) -> object:
        assert depth <= MAX_AUTOMATION_DEPTH, "automation YAML depth limit exceeded"
        self._space()
        assert self.position < len(self.source), f"missing YAML value at line {self.line + 1}"
        character = self.source[self.position]
        if character == "{":
            return self._mapping(depth=depth + 1)
        if character == "[":
            return self._sequence(depth=depth + 1)
        if character in {'"', "'"}:
            return _Scalar(self._quoted(), self.line)
        return _plain_scalar(self._plain(delimiters=",]}"), self.line)

    def _quoted(self) -> str:
        quote = self.source[self.position]
        start = self.position
        self.position += 1
        if quote == "'":
            pieces: list[str] = []
            while self.position < len(self.source):
                character = self.source[self.position]
                self.position += 1
                if character != "'":
                    pieces.append(character)
                elif self.position < len(self.source) and self.source[self.position] == "'":
                    pieces.append("'")
                    self.position += 1
                else:
                    return "".join(pieces)
            raise AssertionError(f"unterminated YAML quote at line {self.line + 1}")
        escaped = False
        while self.position < len(self.source):
            character = self.source[self.position]
            self.position += 1
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                try:
                    return json.loads(self.source[start : self.position])
                except (TypeError, ValueError) as exc:
                    raise AssertionError(
                        f"invalid double-quoted YAML scalar at line {self.line + 1}"
                    ) from exc
        raise AssertionError(f"unterminated YAML quote at line {self.line + 1}")

    def _plain(self, *, delimiters: str) -> str:
        start = self.position
        while self.position < len(self.source) and self.source[self.position] not in delimiters:
            self.position += 1
        return self.source[start : self.position].strip()

    def _key(self) -> str:
        self._space()
        if self.source[self.position] in {'"', "'"}:
            key = self._quoted()
        else:
            key = self._plain(delimiters=":")
        assert key and key != "<<", f"invalid YAML mapping key at line {self.line + 1}"
        self._space()
        assert self.position < len(self.source) and self.source[self.position] == ":", (
            f"missing YAML mapping colon at line {self.line + 1}"
        )
        self.position += 1
        return key

    def _mapping(self, *, depth: int) -> dict:
        self.position += 1
        result: dict[str, object] = {}
        self._space()
        if self.position < len(self.source) and self.source[self.position] == "}":
            self.position += 1
            return result
        while True:
            key = self._key()
            assert key not in result, f"duplicate YAML key {key!r} at line {self.line + 1}"
            result[key] = self._value(depth=depth)
            self._space()
            assert self.position < len(self.source), (
                f"unterminated YAML mapping at line {self.line + 1}"
            )
            character = self.source[self.position]
            self.position += 1
            if character == "}":
                return result
            assert character == ",", f"invalid YAML mapping at line {self.line + 1}"

    def _sequence(self, *, depth: int) -> list:
        self.position += 1
        result: list[object] = []
        self._space()
        if self.position < len(self.source) and self.source[self.position] == "]":
            self.position += 1
            return result
        while True:
            result.append(self._value(depth=depth))
            self._space()
            assert self.position < len(self.source), (
                f"unterminated YAML sequence at line {self.line + 1}"
            )
            character = self.source[self.position]
            self.position += 1
            if character == "]":
                return result
            assert character == ",", f"invalid YAML sequence at line {self.line + 1}"


class _YamlParser:
    def __init__(self, lines: tuple[_Line, ...]):
        self.lines = lines

    def parse(self) -> object:
        assert self.lines, "automation YAML is empty"
        assert self.lines[0].indent == 0, "automation YAML root must begin at column zero"
        result, index = self._block(0, indent=0, depth=0)
        assert index == len(self.lines), (
            f"unexpected YAML indentation at line {self.lines[index].number + 1}"
        )
        return result

    def _block(self, index: int, *, indent: int, depth: int) -> tuple[object, int]:
        assert depth <= MAX_AUTOMATION_DEPTH, "automation YAML depth limit exceeded"
        assert index < len(self.lines) and self.lines[index].indent == indent
        if self.lines[index].content == "-" or self.lines[index].content.startswith("- "):
            return self._sequence(index, indent=indent, depth=depth + 1)
        return self._mapping(index, indent=indent, depth=depth + 1)

    def _value(self, source: str, *, line: int) -> object:
        source = source.strip()
        if source.startswith(("{", "[", '"', "'")):
            return _FlowParser(source, line).parse()
        return _plain_scalar(source, line)

    def _key(self, source: str, *, line: int) -> str:
        source = source.strip()
        assert source, f"empty YAML key at line {line + 1}"
        if source.startswith(('"', "'")):
            parsed = _FlowParser(source, line).parse()
            assert isinstance(parsed, _Scalar) and isinstance(parsed.value, str)
            key = parsed.value
        else:
            assert not source.startswith(("&", "*", "!", "?")), (
                f"unsupported YAML key at line {line + 1}"
            )
            key = source
        assert key != "<<", f"YAML merge keys are forbidden at line {line + 1}"
        return key

    def _entry(
        self,
        line: _Line,
        source: str,
        next_index: int,
        *,
        parent_indent: int,
        depth: int,
    ) -> tuple[str, object, int]:
        separator = _mapping_separator(source)
        assert separator is not None, f"expected YAML mapping at line {line.number + 1}"
        key = self._key(source[:separator], line=line.number)
        remainder = source[separator + 1 :].strip()
        if line.block_scalar is not None:
            assert _BLOCK_HEADER.fullmatch(remainder), line.number + 1
            return key, _Scalar(line.block_scalar, line.number), next_index
        if remainder:
            return key, self._value(remainder, line=line.number), next_index
        if next_index < len(self.lines) and self.lines[next_index].indent > parent_indent:
            child_indent = self.lines[next_index].indent
            child, next_index = self._block(next_index, indent=child_indent, depth=depth + 1)
            return key, child, next_index
        return key, _Scalar(None, line.number), next_index

    def _mapping(self, index: int, *, indent: int, depth: int) -> tuple[dict, int]:
        result: dict[str, object] = {}
        while index < len(self.lines):
            line = self.lines[index]
            if line.indent < indent:
                break
            assert line.indent == indent, f"unexpected indentation at line {line.number + 1}"
            if line.content == "-" or line.content.startswith("- "):
                break
            key, value, index = self._entry(
                line,
                line.content,
                index + 1,
                parent_indent=indent,
                depth=depth,
            )
            assert key not in result, f"duplicate YAML key {key!r} at line {line.number + 1}"
            result[key] = value
        return result, index

    def _sequence(self, index: int, *, indent: int, depth: int) -> tuple[list, int]:
        result: list[object] = []
        while index < len(self.lines):
            line = self.lines[index]
            if line.indent < indent:
                break
            assert line.indent == indent, f"unexpected indentation at line {line.number + 1}"
            if not (line.content == "-" or line.content.startswith("- ")):
                break
            remainder = line.content[1:].strip()
            next_index = index + 1
            if not remainder:
                assert next_index < len(self.lines) and self.lines[next_index].indent > indent, (
                    f"empty YAML sequence item at line {line.number + 1}"
                )
                item, index = self._block(
                    next_index,
                    indent=self.lines[next_index].indent,
                    depth=depth + 1,
                )
                result.append(item)
                continue
            separator = _mapping_separator(remainder)
            if separator is None:
                assert line.block_scalar is None, line.number + 1
                result.append(self._value(remainder, line=line.number))
                index = next_index
                continue

            key, value, index = self._entry(
                line,
                remainder,
                next_index,
                parent_indent=indent,
                depth=depth,
            )
            item = {key: value}
            if index < len(self.lines) and self.lines[index].indent > indent:
                continuation_indent = self.lines[index].indent
                continuation, index = self._mapping(
                    index,
                    indent=continuation_indent,
                    depth=depth + 1,
                )
                for continuation_key, continuation_value in continuation.items():
                    assert continuation_key not in item, (
                        f"duplicate YAML key {continuation_key!r} "
                        f"at line {self.lines[index - 1].number + 1}"
                    )
                    item[continuation_key] = continuation_value
            result.append(item)
        return result, index


def _unwrap_yaml(node: object) -> tuple[object, tuple[dict, ...]]:
    uses: list[dict] = []
    nodes = 0

    def unwrap(current: object, *, depth: int) -> object:
        nonlocal nodes
        nodes += 1
        assert nodes <= MAX_AUTOMATION_NODES, "automation YAML node limit exceeded"
        assert depth <= MAX_AUTOMATION_DEPTH, "automation YAML depth limit exceeded"
        if isinstance(current, _Scalar):
            return current.value
        if isinstance(current, list):
            return [unwrap(value, depth=depth + 1) for value in current]
        if isinstance(current, dict):
            result = {}
            for key, value in current.items():
                if key == "uses":
                    assert isinstance(value, _Scalar) and isinstance(value.value, str), (
                        "uses must be a scalar string"
                    )
                    uses.append({"value": value.value, "line": value.line})
                result[key] = unwrap(value, depth=depth + 1)
            return result
        raise AssertionError(f"unsupported YAML node: {type(current).__name__}")

    return unwrap(node, depth=0), tuple(uses)


def _workflow_paths(workflows: Path = WORKFLOWS) -> tuple[Path, ...]:
    return tuple(sorted({*workflows.glob("*.yml"), *workflows.glob("*.yaml")}))


def _automation_paths(
    workflows: Path = WORKFLOWS,
    actions: Path = ACTIONS,
) -> tuple[Path, ...]:
    return tuple(
        sorted(
            {
                *_workflow_paths(workflows),
                *actions.rglob("action.yml"),
                *actions.rglob("action.yaml"),
            }
        )
    )


def _texts(paths: tuple[Path, ...]):
    return {path.relative_to(ROOT).as_posix(): path.read_text() for path in paths}


def _workflow_texts():
    return _texts(_workflow_paths())


def _automation_texts():
    return _texts(_automation_paths())


def _stat_identity(value: stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _load_yaml(path: Path) -> tuple[dict, tuple[dict, ...], tuple[str, ...]]:
    try:
        state = path.lstat()
        payload = path.read_bytes()
        final = path.lstat()
    except OSError as exc:
        raise AssertionError(f"cannot read automation YAML {path}: {exc}") from exc
    assert stat.S_ISREG(state.st_mode), f"automation YAML is not a regular file: {path}"
    assert 0 < state.st_size <= MAX_AUTOMATION_BYTES, (
        path,
        state.st_size,
        MAX_AUTOMATION_BYTES,
    )
    assert len(payload) == state.st_size, f"automation YAML changed while read: {path}"
    assert _stat_identity(final) == _stat_identity(state), (
        f"automation YAML changed while read: {path}"
    )
    try:
        source = payload.decode("utf-8")
    except UnicodeError as exc:
        raise AssertionError(f"automation YAML is not UTF-8: {path}") from exc
    parsed = _YamlParser(_logical_lines(source)).parse()
    data, uses = _unwrap_yaml(parsed)
    assert isinstance(data, dict), f"automation YAML root is not a mapping: {path}"
    for entry in uses:
        assert isinstance(entry, dict) and set(entry) == {"line", "value"}, (path, entry)
        assert type(entry["line"]) is int and entry["line"] >= 0, (path, entry)
        assert isinstance(entry["value"], str) and entry["value"], (path, entry)
    return data, uses, tuple(source.splitlines())


def _walk_mappings(value: object) -> Iterator[dict]:
    stack = [value]
    nodes = 0
    while stack:
        current = stack.pop()
        nodes += 1
        assert nodes <= MAX_AUTOMATION_NODES, "automation YAML node limit exceeded"
        if isinstance(current, dict):
            yield current
            stack.extend(reversed(tuple(current.values())))
        elif isinstance(current, list):
            stack.extend(reversed(current))


def _reviewed_version_comment(
    path: Path,
    lines: tuple[str, ...],
    entry: dict,
    expected: str,
) -> None:
    line_number = entry["line"]
    assert line_number < len(lines), (path, entry)
    code, marker, comment = lines[line_number].partition("#")
    assert entry["value"] in code, (
        path,
        line_number + 1,
        "external uses must be a one-line scalar",
    )
    assert marker and comment.strip() == expected, (
        path,
        line_number + 1,
        f"expected reviewed tag comment # {expected}",
    )


def _resolve_local_action(
    reference: str,
    *,
    root: Path,
    actions: Path,
    scanned: frozenset[Path],
) -> Path:
    assert reference.startswith("./") and "\\" not in reference, (reference, "local action form")
    relative = PurePosixPath(reference[2:])
    assert relative.parts and all(part not in {"", ".", ".."} for part in relative.parts), (
        reference,
        "local action path",
    )
    target = root.joinpath(*relative.parts)
    try:
        target_state = target.lstat()
        resolved_target = target.resolve(strict=True)
        resolved_actions = actions.resolve(strict=True)
    except OSError as exc:
        raise AssertionError(f"cannot resolve local action {reference}: {exc}") from exc
    assert stat.S_ISDIR(target_state.st_mode), (reference, "local action target is not a directory")
    try:
        resolved_target.relative_to(resolved_actions)
    except ValueError as exc:
        raise AssertionError(f"local action is outside .github/actions: {reference}") from exc
    candidates = tuple(
        path
        for path in (target / "action.yml", target / "action.yaml")
        if path.exists() or path.is_symlink()
    )
    assert len(candidates) == 1, (
        reference,
        "local action must contain exactly one action.yml or action.yaml",
    )
    definition = candidates[0]
    definition_state = definition.lstat()
    assert stat.S_ISREG(definition_state.st_mode), (reference, "action definition is not regular")
    assert definition in scanned, (reference, "local action definition escaped the automation scan")
    return definition


def _audit_external_actions(
    *,
    root: Path = ROOT,
    workflows: Path = WORKFLOWS,
    actions: Path = ACTIONS,
) -> tuple[str, ...]:
    paths = _automation_paths(workflows, actions)
    scanned = frozenset(paths)
    observed: list[str] = []
    for path in paths:
        _data, uses, lines = _load_yaml(path)
        for entry in uses:
            reference = entry["value"]
            if reference.startswith("./"):
                _resolve_local_action(reference, root=root, actions=actions, scanned=scanned)
                continue
            match = _EXTERNAL_USE.fullmatch(reference)
            assert match is not None, (path, reference, "external action is not full-SHA pinned")
            action, commit = match.group("action", "commit")
            assert action in ALLOWED_ACTIONS, (path, action)
            expected_commit, expected_version = ALLOWED_ACTIONS[action]
            assert commit == expected_commit, (path, action, commit)
            _reviewed_version_comment(path, lines, entry, expected_version)
            observed.append(action)
    return tuple(observed)


def _audit_runner_labels(workflows: Path = WORKFLOWS) -> None:
    allowed = {"ubuntu-24.04", "macos-15", "windows-2025"}
    for path in _workflow_paths(workflows):
        data, _uses, _lines = _load_yaml(path)
        jobs = data.get("jobs")
        assert isinstance(jobs, dict) and jobs, (path, "jobs")
        for name, job in jobs.items():
            assert isinstance(name, str) and isinstance(job, dict), (path, name)
            label = job.get("runs-on")
            assert isinstance(label, str) and label in allowed, (path, name, label)


def _audit_checkout_credentials(
    workflows: Path = WORKFLOWS,
    actions: Path = ACTIONS,
) -> None:
    for path in _automation_paths(workflows, actions):
        data, _uses, _lines = _load_yaml(path)
        for mapping in _walk_mappings(data):
            reference = mapping.get("uses")
            if not isinstance(reference, str) or not reference.startswith("actions/checkout@"):
                continue
            settings = mapping.get("with")
            assert isinstance(settings, dict), (path, "checkout has no with mapping")
            assert settings.get("persist-credentials") is False, (
                path,
                "checkout must set boolean persist-credentials: false",
            )


def test_automation_discovery_covers_both_workflow_suffixes_and_composite_actions(
    tmp_path: Path,
):
    workflows = tmp_path / "workflows"
    actions = tmp_path / "actions"
    workflows.mkdir()
    (actions / "nested").mkdir(parents=True)
    expected = {
        workflows / "one.yml",
        workflows / "two.yaml",
        actions / "action.yml",
        actions / "nested" / "action.yaml",
    }
    for path in expected:
        path.write_text("name: fixture\n")
    (workflows / "ignored.txt").write_text("uses: attacker/example@main\n")
    (actions / "nested" / "other.yml").write_text("uses: attacker/example@main\n")
    assert set(_automation_paths(workflows, actions)) == expected


def test_every_external_action_is_an_allowlisted_full_commit_with_reviewed_tag_comment():
    observed = _audit_external_actions()
    assert set(observed) == set(ALLOWED_ACTIONS)


def test_hosted_runner_os_labels_are_explicit_not_rolling_aliases():
    _audit_runner_labels()


def test_checkout_never_persists_a_workflow_token_in_the_repository():
    _audit_checkout_credentials()


def _hostile_repo(tmp_path: Path, workflow: str) -> tuple[Path, Path, Path]:
    root = tmp_path / "repository"
    workflows = root / ".github" / "workflows"
    actions = root / ".github" / "actions"
    workflows.mkdir(parents=True)
    actions.mkdir(parents=True)
    (workflows / "hostile.yaml").write_text(workflow)
    return root, workflows, actions


def test_semantic_action_audit_catches_spaced_colons_and_unpinned_references(
    tmp_path: Path,
) -> None:
    root, workflows, actions = _hostile_repo(
        tmp_path,
        """\
jobs:
  hostile:
    runs-on: ubuntu-24.04
    steps:
      - uses : actions/checkout@main # v6.0.2
        with: {persist-credentials: false}
""",
    )
    with pytest.raises(AssertionError, match="full-SHA pinned"):
        _audit_external_actions(root=root, workflows=workflows, actions=actions)


def test_bounded_parser_uses_yaml_12_on_semantics_and_ignores_block_scalar_text(
    tmp_path: Path,
) -> None:
    root, workflows, actions = _hostile_repo(
        tmp_path,
        """\
on:
  push:
jobs:
  safe:
    runs-on : ubuntu-24.04
    steps:
      - name: text is not a node
        run: |
          uses : attacker/example@main
          runs-on : ubuntu-latest
          persist-credentials: true
""",
    )
    data, uses, _lines = _load_yaml(workflows / "hostile.yaml")
    assert data["on"] == {"push": None}
    assert uses == ()
    _audit_runner_labels(workflows)
    assert _audit_external_actions(root=root, workflows=workflows, actions=actions) == ()


def test_semantic_runner_and_checkout_audits_catch_inline_mappings(
    tmp_path: Path,
) -> None:
    commit, version = ALLOWED_ACTIONS["actions/checkout"]
    root, workflows, actions = _hostile_repo(
        tmp_path,
        (
            "jobs: {hostile: {runs-on : ubuntu-latest, steps: "
            f"[{{uses : actions/checkout@{commit}, "
            "with: {persist-credentials: true}}]}} # "
            f"{version}\n"
        ),
    )
    with pytest.raises(AssertionError, match="ubuntu-latest"):
        _audit_runner_labels(workflows)
    with pytest.raises(AssertionError, match="boolean persist-credentials"):
        _audit_checkout_credentials(workflows, actions)
    assert _audit_external_actions(root=root, workflows=workflows, actions=actions) == (
        "actions/checkout",
    )


def test_local_actions_are_resolved_and_their_nested_steps_are_scanned(
    tmp_path: Path,
) -> None:
    root, workflows, actions = _hostile_repo(
        tmp_path,
        """\
jobs:
  hostile:
    runs-on: ubuntu-24.04
    steps:
      - {uses : ./.github/actions/outer}
""",
    )
    outer = actions / "outer"
    inner = actions / "inner"
    outer.mkdir()
    inner.mkdir()
    (outer / "action.yml").write_text(
        """\
name: outer
runs:
  using: composite
  steps:
    - {uses : ./.github/actions/inner}
"""
    )
    (inner / "action.yaml").write_text(
        """\
name: inner
runs:
  using: composite
  steps:
    - uses : actions/upload-artifact@main # v7.0.1
"""
    )
    with pytest.raises(AssertionError, match="full-SHA pinned"):
        _audit_external_actions(root=root, workflows=workflows, actions=actions)

    commit, version = ALLOWED_ACTIONS["actions/upload-artifact"]
    (inner / "action.yaml").write_text(
        f"""\
name: inner
runs:
  using: composite
  steps:
    - {{uses : actions/upload-artifact@{commit}}} # {version}
"""
    )
    assert _audit_external_actions(root=root, workflows=workflows, actions=actions) == (
        "actions/upload-artifact",
    )


@pytest.mark.parametrize("reference", ["./outside", "./.github/actions/missing"])
def test_local_action_reference_must_resolve_under_scanned_github_actions(
    tmp_path: Path,
    reference: str,
) -> None:
    root, workflows, actions = _hostile_repo(
        tmp_path,
        f"""\
jobs:
  hostile:
    runs-on: ubuntu-24.04
    steps:
      - uses: {reference}
""",
    )
    if reference == "./outside":
        outside = root / "outside"
        outside.mkdir()
        (outside / "action.yml").write_text("name: outside\nruns: {using: composite, steps: []}\n")
    with pytest.raises(AssertionError, match="local action"):
        _audit_external_actions(root=root, workflows=workflows, actions=actions)


def test_semantic_audit_rejects_duplicate_keys_and_ambiguous_local_definitions(
    tmp_path: Path,
) -> None:
    root, workflows, actions = _hostile_repo(
        tmp_path,
        """\
jobs:
  hostile:
    runs-on: ubuntu-24.04
    steps:
      - uses: ./.github/actions/ambiguous
        uses : actions/checkout@main
""",
    )
    with pytest.raises(AssertionError, match="duplicate YAML key 'uses'"):
        _audit_external_actions(root=root, workflows=workflows, actions=actions)

    (workflows / "hostile.yaml").write_text(
        """\
jobs:
  hostile:
    runs-on: ubuntu-24.04
    steps:
      - uses: ./.github/actions/ambiguous
"""
    )
    ambiguous = actions / "ambiguous"
    ambiguous.mkdir()
    for name in ("action.yml", "action.yaml"):
        (ambiguous / name).write_text("name: ambiguous\nruns: {using: composite, steps: []}\n")
    with pytest.raises(AssertionError, match="exactly one action.yml or action.yaml"):
        _audit_external_actions(root=root, workflows=workflows, actions=actions)


def test_uv_bootstrap_is_one_version_and_exactly_three_reviewed_platform_wheels():
    path = ROOT / "ci-bootstrap-requirements.txt"
    text = path.read_text()
    requirements = [line for line in text.splitlines() if line and not line.startswith("#")]
    assert requirements[0] == "uv==0.11.17 \\"
    hashes = set(re.findall(r"--hash=sha256:([0-9a-f]{64})", text))
    assert hashes == UV_HASHES
    assert text.count("--hash=sha256:") == 3
    assert "http://" not in text
    assert "https://pypi.org/pypi/uv/<version>/json" in text


def test_every_uv_bootstrap_install_is_closed_and_hash_enforced():
    combined = "\n".join(_workflow_texts().values())
    installs = re.findall(
        r"(?:python\"|\$python) -m pip install --quiet --disable-pip-version-check "
        r"(?:\\|`)\n\s+([^\n]+)",
        combined,
    )
    # Eight CI jobs plus the manual release-evidence workflow.
    assert len(installs) == 9, installs
    expected = "--no-deps --only-binary=:all: --require-hashes -r ci-bootstrap-requirements.txt"
    assert all(line.strip() == expected for line in installs)
    assert '"uv==$UV_VERSION"' not in combined
    assert '"uv==$env:UV_VERSION"' not in combined


def test_dependabot_tracks_the_pinned_github_actions():
    text = (ROOT / ".github" / "dependabot.yml").read_text()
    assert "version: 2" in text
    assert "package-ecosystem: github-actions" in text
    assert "directory: /" in text
    assert "interval: weekly" in text


def test_release_evidence_workflow_is_manual_tag_only_and_has_no_publisher():
    text = (WORKFLOWS / "release-evidence.yml").read_text()
    assert "workflow_dispatch:" in text
    assert "if: startsWith(github.ref, 'refs/tags/v')" in text
    assert "push:" not in text and "release:" not in text.split("jobs:", 1)[0]
    assert "id-token: write" in text
    assert "attestations: write" in text
    assert "artifact-metadata: write" in text
    assert "environment: release-attestation" in text
    assert 'git rev-parse "$GITHUB_REF^{}"' in text
    for suite in (
        "tests/test_release_evidence.py",
        "tests/test_publish_rehearsal.py",
        "tests/test_cyclonedx_schema.py",
        "tests/test_workflow_supply_chain.py",
    ):
        assert suite in text
    assert ".venv/bin/python scripts/publish_rehearsal.py" in text
    assert "uv publish" not in text
    assert "pypi.org" not in text
    assert "gh release" not in text
    assert "git push" not in text


def test_every_publish_rehearsal_scrubs_configuration_and_remote_overrides():
    combined = "\n".join(_workflow_texts().values())
    wrapper = ".venv/bin/python scripts/publish_rehearsal.py"
    assert combined.count(wrapper) == 2
    assert combined.count('"$RUNNER_TEMP/artifactforge-release-evidence/dist"') == 2
    assert combined.count('--uv "$RUNNER_TEMP/artifactforge-uv-bootstrap/bin/uv"') >= 6
    assert "uv publish" not in combined


def test_distribution_builds_are_closed_and_ignore_local_source_overrides():
    combined = "\n".join(_workflow_texts().values()).replace("\\\n", " ")
    build_commands = [line for line in combined.splitlines() if "uv build " in line]
    assert len(build_commands) == 5, build_commands
    for command in build_commands:
        assert "--no-sources" in command
        assert "--no-create-gitignore" in command
        assert "--build-constraint build-constraints.txt" in command
        assert "--require-hashes" in command


def test_release_inputs_do_not_dirty_the_checkout_before_source_capture():
    text = (WORKFLOWS / "ci.yml").read_text()
    assert "fixture-run/" not in text
    assert 'FIXTURE_RUN="$RUNNER_TEMP/artifactforge-fixture-run"' in text
    assert 'test -z "$(git status --porcelain --untracked-files=all)"' in text
    assert text.index('test -z "$(git status --porcelain --untracked-files=all)"') < text.index(
        "PYTHONHASHSEED=1 TZ=UTC LC_ALL=C uv build"
    )


def test_sample_regeneration_keeps_gate4_source_provenance_clean():
    text = (WORKFLOWS / "ci.yml").read_text()
    samples_start = text.index("- name: Samples — regenerate and byte-diff")
    gate4_start = text.index("- name: Gate 4 — solvability", samples_start)
    determinism_start = text.index("- name: Determinism — regenerate", gate4_start)
    samples = text[samples_start:gate4_start]
    gate4 = text[gate4_start:determinism_start]

    assert 'SAMPLES_BASELINE="$RUNNER_TEMP/artifactforge-samples-committed"' in samples
    assert 'cp -R samples "$SAMPLES_BASELINE"' in samples
    assert 'diff -r "$SAMPLES_BASELINE" samples' in samples
    assert "samples.committed" not in samples

    cleanliness = 'test -z "$(git status --porcelain --untracked-files=all)"'
    scorecard = "uv run artifactforge scorecard --n 40"
    assert cleanliness in gate4
    assert gate4.index(cleanliness) < gate4.index(scorecard)
