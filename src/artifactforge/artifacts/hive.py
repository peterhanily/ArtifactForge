"""Minimal deterministic regf (Windows registry hive) writer — validated by regipy.

Two passes: (1) assign every cell an offset (an nk's offset is reserved before its
children so they can point back at it); (2) serialize in the identical order. Offsets are
relative to the first hive bin (file offset 4096). Enough of the format to carry Run-key
persistence and Amcache InventoryApplicationFile entries; disk-image tiers are out of scope.
"""
from __future__ import annotations

import struct

FILETIME = 133497684000000000  # 2024-01-15T05:00:00Z, pinned (deterministic)
REG_SZ, REG_BINARY, REG_DWORD = 1, 3, 4
_NONE = 0xFFFFFFFF


class Val:
    def __init__(self, name: str, type_: int, data: bytes):
        self.name, self.type, self.data = name, type_, data


class Key:
    def __init__(self, name: str, values=None, subkeys=None):
        self.name = name
        self.values = values or []
        self.subkeys = subkeys or []


def sz(name: str, value: str) -> Val:
    return Val(name, REG_SZ, (value + "\x00").encode("utf-16-le"))


def dword(name: str, value: int) -> Val:
    return Val(name, REG_DWORD, value.to_bytes(4, "little"))


def _padded_total(data_size: int) -> int:
    total = 4 + data_size
    return total + ((-total) % 8)


def build_hive(root: Key) -> bytes:
    running = 0

    def alloc(data_size: int) -> int:
        nonlocal running
        off = 32 + running
        running += _padded_total(data_size)
        return off

    def assign(key: Key):
        key._name = key.name.encode("latin-1")
        key._nk = alloc(76 + len(key._name))
        for v in key.values:
            v._name = v.name.encode("latin-1")
            v._inline = (v.type == REG_DWORD and len(v.data) <= 4)
            if not v._inline:
                v._data = alloc(len(v.data))
            v._vk = alloc(20 + len(v._name))
        key._vlist = alloc(4 * len(key.values)) if key.values else _NONE
        for c in key.subkeys:
            c._parent = key._nk
            assign(c)
        key._sklist = alloc(4 + 8 * len(key.subkeys)) if key.subkeys else _NONE

    root._parent = 0
    assign(root)             # root nk is the FIRST cell (regipy treats cell #1 as the root)
    sk_off = alloc(20)       # shared security cell, emitted last

    hbin_size = ((32 + running + 4095) // 4096) * 4096
    cells = bytearray()

    def emit(body: bytes):
        total = _padded_total(len(body))
        cells.extend(struct.pack("<i", -total) + body + b"\x00" * (total - 4 - len(body)))

    def write(key: Key, is_root=False):
        flags = 0x20 | (0x0C if is_root else 0)  # KEY_COMP_NAME (+ HIVE_ENTRY|NO_DELETE for root)
        emit(b"nk" + struct.pack(
            "<HQIIIIIIIIIIIIIIIHH",
            flags, FILETIME, 0, key._parent,
            len(key.subkeys), 0, key._sklist, _NONE,
            len(key.values), key._vlist, sk_off, _NONE,
            0, 0, 0, 0, 0,
            len(key._name), 0) + key._name)
        for v in key.values:
            if v._inline:
                data_off = int.from_bytes(v.data.ljust(4, b"\x00")[:4], "little")
                data_size = 0x80000000 | len(v.data)
            else:
                emit(v.data)
                data_off, data_size = v._data, len(v.data)
            vflags = 0x0001 if v._name else 0
            emit(b"vk" + struct.pack("<HIIIHH", len(v._name), data_size, data_off, v.type, vflags, 0) + v._name)
        if key.values:
            emit(b"".join(struct.pack("<I", v._vk) for v in key.values))
        for c in key.subkeys:
            write(c)
        if key.subkeys:
            body = b"lf" + struct.pack("<H", len(key.subkeys))
            for c in key.subkeys:
                body += struct.pack("<I", c._nk) + c._name[:4].ljust(4, b"\x00")
            emit(body)

    write(root, is_root=True)
    emit(b"sk\x00\x00" + struct.pack("<IIII", 0, 0, 1, 0))  # shared security cell

    free = hbin_size - 32 - len(cells)
    if free >= 4:
        cells.extend(struct.pack("<i", free) + b"\x00" * (free - 4))

    hbin = (b"hbin" + struct.pack("<II", 0, hbin_size) + b"\x00" * 8
            + struct.pack("<Q", FILETIME) + b"\x00" * 4 + bytes(cells))
    hbin = hbin[:hbin_size].ljust(hbin_size, b"\x00")

    base = bytearray(4096)
    base[0:4] = b"regf"
    struct.pack_into("<II", base, 4, 1, 1)
    struct.pack_into("<Q", base, 12, FILETIME)
    struct.pack_into("<IIII", base, 20, 1, 3, 0, 1)
    struct.pack_into("<I", base, 36, root._nk)
    struct.pack_into("<I", base, 40, hbin_size)
    struct.pack_into("<I", base, 44, 1)
    name = "ArtifactForgeHive".encode("utf-16-le")[:64]
    base[48:48 + len(name)] = name
    checksum = 0
    for i in range(0, 508, 4):
        checksum ^= struct.unpack_from("<I", base, i)[0]
    if checksum in (0, 0xFFFFFFFF):
        checksum ^= 1
    struct.pack_into("<I", base, 508, checksum & 0xFFFFFFFF)
    return bytes(base) + hbin


def build_run_hive(value_name: str, exe_path: str) -> bytes:
    """A SOFTWARE-hive fragment: ...\\CurrentVersion\\Run with one autostart value."""
    return build_hive(Key("ROOT", subkeys=[Key("Microsoft", subkeys=[
        Key("Windows", subkeys=[Key("CurrentVersion", subkeys=[
            Key("Run", values=[sz(value_name, exe_path)])])])])]))


def build_amcache_hive(sha1: str, lower_path: str, name: str, size: int) -> bytes:
    """An Amcache.hve fragment: Root\\InventoryApplicationFile\\<entry>, FileId = 0000+SHA1."""
    entry = Key("0000" + sha1[:8], values=[
        sz("FileId", "0000" + sha1),
        sz("LowerCaseLongPath", lower_path),
        sz("Name", name),
        dword("Size", size),
    ])
    return build_hive(Key("amcache", subkeys=[
        Key("Root", subkeys=[Key("InventoryApplicationFile", subkeys=[entry])])]))
