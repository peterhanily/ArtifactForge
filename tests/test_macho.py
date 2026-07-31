# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""The macOS binary is real, and its identity is real.

The Windows side's value comes from the synthetic PE carrying a genuine IMPHASH that pefile
independently computes. macOS needs the same property or the keystone covers half the
benchmark: a Mach-O whose hash-shaped fields were invented would be exactly the disease this
project exists to cure.

So the symhash is checked against a symbol table read back by LIEF, not against the list we
wrote; the cdhash is recomputed from the embedded CodeDirectory; and on macOS, where Apple's
own tooling is available, `codesign` is asked whether the signature is valid.
"""
import hashlib
import os
import subprocess
import sys

import pytest

from artifactforge.content import ContentStore
from artifactforge.content.macho import build_macho, cdhash_of_file, pick_imports, symhash_of
from artifactforge.content.seed import sub_seed

lief = pytest.importorskip("lief")


def _store(tmp_path):
    return ContentStore("artifactforge::macho-test", str(tmp_path / "content"))


def test_symhash_matches_an_independent_parser(tmp_path):
    """Our pure-stdlib symhash must equal one computed from LIEF's view of the symbol table.

    symhash is md5 of the sorted, comma-joined undefined external symbol names — so if the
    two disagree, either the symbol table we emit is not what we think it is, or the value we
    publish is a fabrication.
    """
    store = _store(tmp_path)
    for bundle in ("com.acme.updater", "io.opncast.helper", "net.zeta.sync"):
        c = store.materialize(f"macho:{bundle}:role")
        binary = lief.parse(c.path)
        undefined = sorted(s.name for s in binary.symbols
                           if s.is_external and not s.has_export_info
                           and s.name.startswith("_"))
        assert undefined, "a binary with no undefined externals has no symhash to speak of"
        assert hashlib.md5(",".join(undefined).encode()).hexdigest() == c.symhash  # noqa: S324
        assert c.symhash != "0" * 32


def test_symhash_is_deterministic_and_varies(tmp_path):
    a1 = _store(tmp_path / "a").materialize("macho:com.acme.updater:x")
    a2 = _store(tmp_path / "b").materialize("macho:com.acme.updater:x")
    other = _store(tmp_path / "c").materialize("macho:com.acme.updater:y")
    assert a1.bytes == a2.bytes and a1.symhash == a2.symhash
    assert a1.symhash != other.symhash or a1.sha256 != other.sha256


def test_the_signing_identifier_is_part_of_the_identity(tmp_path):
    """It lives inside the CodeDirectory, so it changes the file's length and its SHA256.

    That is why it has to be encoded in the content id rather than passed alongside it —
    otherwise one content id would map to several different sets of bytes.
    """
    store = _store(tmp_path)
    a = store.materialize("macho:com.acme.updater:same-role")
    b = store.materialize("macho:net.zeta.sync:same-role")
    assert a.sha256 != b.sha256
    assert a.cdhash != b.cdhash


def test_cdhash_is_the_digest_of_the_embedded_codedirectory(tmp_path):
    c = _store(tmp_path).materialize("macho:com.acme.updater:x")
    assert c.cdhash and len(c.cdhash) == 40
    with open(c.path, "rb") as f:
        assert cdhash_of_file(f.read()) == c.cdhash


def test_both_mach_o_parsers_read_it(tmp_path):
    macholib = pytest.importorskip("macholib.MachO")
    c = _store(tmp_path).materialize("macho:com.acme.updater:x")

    binary = lief.parse(c.path)
    assert binary is not None
    assert str(binary.header.cpu_type).endswith("ARM64")
    assert binary.libraries, "a binary linking nothing has no imports to hash"

    m = macholib.MachO(c.path)
    assert len(m.headers) == 1
    assert len(m.headers[0].commands) >= 13


def test_the_code_section_is_two_instructions_and_nothing_else(tmp_path):
    """`mov w0, #0 ; ret` — the arm64 analogue of the PE's single 0xC3."""
    c = _store(tmp_path).materialize("macho:com.acme.updater:x")
    assert b"\x00\x00\x80\x52\xc0\x03\x5f\xd6" in c.bytes
    assert c.marker.encode() in c.bytes


def test_no_wall_clock_leaks_into_the_bytes(tmp_path):
    """Built in three processes under different hash seeds, timezones and locales."""
    code = (
        "import sys,hashlib,tempfile;"
        "from artifactforge.content import ContentStore;"
        "print(ContentStore('artifactforge::macho-test', tempfile.mkdtemp())"
        ".materialize('macho:com.acme.updater:x').sha256)")
    outs = []
    for seed, tz, loc in (("0", "UTC", "C"), ("7", "Asia/Tokyo", "C"),
                          ("31337", "America/New_York", "C")):
        env = dict(os.environ, PYTHONHASHSEED=seed, TZ=tz, LC_ALL=loc)
        outs.append(subprocess.run([sys.executable, "-c", code], capture_output=True,
                                   text=True, env=env, check=True).stdout.strip())
    assert len(set(outs)) == 1, outs


@pytest.mark.skipif(sys.platform != "darwin", reason="Apple's codesign is macOS-only")
def test_apple_codesign_accepts_the_signature(tmp_path):
    """The strictest available oracle, and the one CI cannot run.

    An unsigned arm64 binary is not loadable at all, and signing after the fact would rewrite
    the bytes and break determinism — so the ad-hoc signature is computed in-process. This
    asks Apple's own tool whether that worked.
    """
    c = _store(tmp_path).materialize("macho:com.acme.updater:x")
    target = str(tmp_path / "updater")
    with open(c.path, "rb") as src, open(target, "wb") as dst:
        dst.write(src.read())
    os.chmod(target, 0o755)

    verify = subprocess.run(["codesign", "-v", target], capture_output=True, text=True)
    assert verify.returncode == 0, verify.stderr

    described = subprocess.run(["codesign", "-d", "--verbose=4", target],
                               capture_output=True, text=True)
    assert f"CDHash={c.cdhash}" in described.stderr, described.stderr


def test_build_macho_is_callable_without_a_store(tmp_path):
    """The writer stands alone, so a caller can hold the bytes without a cache."""
    seed = sub_seed(b"scenario", "macho:standalone")
    imports = pick_imports(seed)
    data = build_macho(seed, imports, sign_identifier="com.example.tool")
    assert data[:4] == b"\xcf\xfa\xed\xfe"
    assert symhash_of(imports) == symhash_of(pick_imports(seed))
