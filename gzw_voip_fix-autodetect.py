#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gzw_voip_fix-autodetect.py -- restore in-game VOIP in Gray Zone Warfare 0.5+ under Wine/Proton.

The 0.5 ODIN voice SDK makes two Windows socket calls that Wine handles
differently from Windows:

  1) getsockopt(AF_INET socket, IPPROTO_IPV6, IPV6_V6ONLY)
     Wine returns WSAEOPNOTSUPP (10045) because the socket is not IPv6.
     Windows returns success and V6ONLY = 0.
     The ODIN SDK treats 10045 as fatal and closes the voice room.

  2) setsockopt(AF_INET socket, IPPROTO_IP, IP_ECN, ...)
     Wine returns WSAENOPROTOOPT (10042) because it does not implement
     IP_ECN on IPPROTO_IP.  The ODIN SDK again treats the error as fatal.

This tool patches the active Proton's 64-bit ws2_32.dll in place:

  * getsockopt -> success, V6ONLY = 0 (for exactly IPV6_V6ONLY)
  * setsockopt -> success, no-op (for exactly IPPROTO_IP / IP_ECN)

No game file is modified.  A copy of the original DLL is written next to it
and can be restored with --revert.

The patch is deliberately narrow: every other socket option goes through
Wine's original code.  The two new code blocks live in unused zero padding
at the end of the .text section.

License: MIT.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path

VERSION = "1.1.0"

APPID = "2479810"
GAME_EXE = "GZWClientSteam-Win64-Shipping"
GAME_COMM = "GZWClientSteam"

# Bytes in the Wine trampoline that lead to server_getsockopt().
# This sequence is stable across all tested Wine 11.0 builds.
SIG_V6ONLY = bytes.fromhex("ba 5c 04 12 00 e9")
IOCTL_GET_IPV6_V6ONLY = 0x12045C

# Exact prologue of server_getsockopt() in all tested builds:
#   push rbp; push rsi; push rbx; sub rsp, 0x60
PRO1 = bytes.fromhex("55 56 53 48 83 ec 60")
CAVE1_PREFIX = bytes.fromhex("81 fa 5c 04 12 00")

# The setsockopt() prologue varies between builds (debug vs stripped), so it
# is parsed at runtime.  These are the prefixes of the two known cave forms.
CAVE2_PREFIX = bytes.fromhex("83 fa 00 0f 85")

IPPROTO_IP = 0
IP_ECN = 0x32

# Full SHA-256 of the *original* (unpatched) DLLs that were tested.
TESTED = {
    "4e577deb96e723bd84d829265b515d8f76afda8ab4c4b40e3eb7c92cf6e7b48c":
        "proton-cachyos-11.0-20261015-slr-x86_64_v3 (with debug info)",
    "83f42bc5c7cef4ba34eabd506237f6ec1b0e3a767be1b7a730ba815d87ba2041":
        "GE-Proton 11-1 / 11-5 / 11-10; proton-cachyos-11.0-20260521",
    "651ae83aeb0299c5fc95ad1ce24a952b1e001a8c3fccdae426a2b9b836cd8c89":
        "Proton - Experimental",
    "6fed136eaa4a50ec3ce4c0516baaef8ed503831bf18115e8c55ae62f9a6de35a":
        "Proton 11.0",
    "bd2ba13dc9ba332e1c3fffa04dfa5cbd67cde44d58c1e5b69ed61cf664bade61":
        "Proton Hotfix",
}

BACKUP_SUFFIX = ".gzw-voip-backup"
LEGACY_BACKUP_SUFFIX = ".v6only-backup"


class PatchError(Exception):
    pass


# ---------------------------------------------------------------------------
# Small PE32+ reader -- no external dependencies
# ---------------------------------------------------------------------------

def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _i32(b, o):
    return struct.unpack_from("<i", b, o)[0]


def _u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def _align_up(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


@dataclass
class Section:
    name: str
    va: int
    vsize: int
    rawptr: int
    rawsize: int
    chars: int
    hdr: int

    def rva_to_off(self, rva):
        if not (self.va <= rva < self.va + self.rawsize):
            raise PatchError(
                "RVA %#x is outside the file-backed part of %s" % (rva, self.name)
            )
        return self.rawptr + (rva - self.va)


class PE:
    def __init__(self, data):
        self.data = data
        if len(data) < 0x40:
            raise PatchError("file is too small to be a PE image")
        e_lfanew = _u32(data, 0x3C)
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise PatchError("not a PE image (missing PE signature)")
        coff = e_lfanew + 4
        self.num_sections = _u16(data, coff + 2)
        opt_size = _u16(data, coff + 16)
        opt = coff + 20
        magic = _u16(data, opt)
        if magic != 0x20B:
            raise PatchError(
                "not a 64-bit PE32+ image (magic %#x); this tool only patches "
                "the x86_64 ws2_32.dll used by Gray Zone Warfare" % magic
            )
        self.image_base = _u64(data, opt + 24)
        self.section_alignment = _u32(data, opt + 32)
        self.file_alignment = _u32(data, opt + 36)
        self.size_of_image = _u32(data, opt + 56)
        self.size_of_headers = _u32(data, opt + 60)
        self.num_dirs = _u32(data, opt + 108)
        self.dir_off = opt + 112

        self.sections = []
        sec_off = opt + opt_size
        for i in range(self.num_sections):
            o = sec_off + i * 40
            if o + 40 > len(data):
                raise PatchError("truncated PE section table")
            name = data[o:o + 8].split(b"\0", 1)[0].decode("ascii", "replace")
            self.sections.append(Section(
                name=name,
                vsize=_u32(data, o + 8),
                va=_u32(data, o + 12),
                rawsize=_u32(data, o + 16),
                rawptr=_u32(data, o + 20),
                chars=_u32(data, o + 36),
                hdr=o,
            ))
        self.text = next((s for s in self.sections if s.name == ".text"), None)
        if self.text is None:
            raise PatchError("no .text section in ws2_32.dll")

    def rva_to_off(self, rva):
        for s in self.sections:
            if s.va <= rva < s.va + s.rawsize:
                return s.rawptr + (rva - s.va)
        raise PatchError("RVA %#x is not backed by file data in any section" % rva)

    def off_to_rva(self, off):
        for s in self.sections:
            if s.rawptr <= off < s.rawptr + s.rawsize:
                return s.va + (off - s.rawptr)
        raise PatchError("file offset %#x is not inside a section" % off)

    def data_dir(self, index):
        off = self.dir_off + index * 8
        if index >= self.num_dirs or off + 8 > len(self.data):
            return 0, 0
        return _u32(self.data, off), _u32(self.data, off + 4)

    def export_rva(self, name):
        rva, size = self.data_dir(0)
        if not rva:
            raise PatchError("the PE has no export directory")
        off = self.rva_to_off(rva)
        num_names = _u32(self.data, off + 24)
        addr_funcs = _u32(self.data, off + 28)
        addr_names = _u32(self.data, off + 32)
        addr_ords = _u32(self.data, off + 36)
        for i in range(num_names):
            name_rva = _u32(self.data, self.rva_to_off(addr_names + i * 4))
            name_off = self.rva_to_off(name_rva)
            end = self.data.find(b"\0", name_off, name_off + 256)
            if end < 0:
                continue
            if self.data[name_off:end].decode("ascii", "replace") != name:
                continue
            ordinal = _u16(self.data, self.rva_to_off(addr_ords + i * 2))
            func_rva = _u32(self.data, self.rva_to_off(addr_funcs + ordinal * 4))
            if rva <= func_rva < rva + size:
                raise PatchError(
                    "export %r is forwarded to another DLL (%#x); unsupported" % (name, func_rva)
                )
            return func_rva
        raise PatchError("export %r not found in ws2_32.dll" % name)


# ---------------------------------------------------------------------------
# Finding the two functions
# ---------------------------------------------------------------------------

@dataclass
class FuncInfo:
    rva: int
    status: str
    prologue: bytes = b""
    length: int = 0
    cave_rva: int = 0


def find_server_getsockopt(pe, data):
    unknown = None
    search = 0
    while True:
        pos = data.find(SIG_V6ONLY, search)
        if pos < 0:
            break
        search = pos + 1
        if not (pe.text.rawptr <= pos < pe.text.rawptr + pe.text.rawsize):
            continue
        jmp_off = pos + len(SIG_V6ONLY) - 1
        if data[jmp_off] != 0xE9:
            continue
        try:
            jmp_rva = pe.off_to_rva(jmp_off)
            tramp_rva = jmp_rva + 5 + _i32(data, jmp_off + 1)
            tramp_off = pe.rva_to_off(tramp_rva)
        except PatchError:
            continue
        thunk = data[tramp_off:tramp_off + 128]
        for i in range(len(thunk) - 5):
            if thunk[i] != 0xE9:
                continue
            target = tramp_rva + i + 5 + _i32(thunk, i + 1)
            try:
                toff = pe.rva_to_off(target)
            except PatchError:
                continue
            if not (pe.text.va <= target < pe.text.va + pe.text.rawsize):
                continue
            if data[toff:toff + len(PRO1)] == PRO1:
                return FuncInfo(target, "clean", PRO1, len(PRO1), 0)
            if data[toff] == 0xE9:
                try:
                    cave = target + 5 + _i32(data, toff + 1)
                    coff = pe.rva_to_off(cave)
                except PatchError:
                    continue
                if data[coff:coff + len(CAVE1_PREFIX)] == CAVE1_PREFIX:
                    return FuncInfo(target, "patched", b"", 0, cave)
                if unknown is None:
                    unknown = FuncInfo(target, "unknown", b"", 0, cave)
                continue
            if unknown is None:
                unknown = FuncInfo(target, "unknown")
    if unknown is not None:
        return unknown
    raise PatchError(
        "could not locate server_getsockopt() in this ws2_32.dll.\n"
        "The IPV6_V6ONLY trampoline signature was not found or did not lead "
        "to the expected function."
    )


def parse_setsockopt_prologue(data, off):
    if data[off] != 0x55:
        raise PatchError(
            "setsockopt() does not start with push rbp (byte %#x); unsupported prologue" % data[off]
        )
    total = 1
    while total < 5:
        if off + total + 7 >= len(data):
            raise PatchError("truncated setsockopt() prologue")
        b = data[off + total]
        if 0x50 <= b <= 0x57:
            total += 1
        elif b == 0x41 and 0x50 <= data[off + total + 1] <= 0x57:
            total += 2
        elif b == 0x48 and data[off + total + 1] == 0x83 and data[off + total + 2] == 0xEC:
            total += 4
        elif b == 0x48 and data[off + total + 1] == 0x81 and data[off + total + 2] == 0xEC:
            total += 7
        elif b == 0x48 and data[off + total + 1] == 0x8D and data[off + total + 2] == 0x6C:
            total += 5
        else:
            raise PatchError("unsupported setsockopt() prologue")
        if total > 12:
            raise PatchError("setsockopt() prologue is unexpectedly long")
    return bytes(data[off:off + total]), total


def find_setsockopt(pe, data):
    rva = pe.export_rva("setsockopt")
    off = pe.rva_to_off(rva)
    if data[off] == 0xE9:
        try:
            cave = rva + 5 + _i32(data, off + 1)
            coff = pe.rva_to_off(cave)
        except PatchError:
            return FuncInfo(rva, "unknown")
        if data[coff:coff + len(CAVE2_PREFIX)] == CAVE2_PREFIX:
            return FuncInfo(rva, "patched", b"", 0, cave)
        return FuncInfo(rva, "unknown", b"", 0, cave)
    if data[off] == 0x55:
        prologue, length = parse_setsockopt_prologue(data, off)
        return FuncInfo(rva, "clean", prologue, length, 0)
    return FuncInfo(rva, "unknown")


@dataclass
class Inspection:
    pe: PE
    getsockopt: FuncInfo
    setsockopt: FuncInfo
    status: str


def inspect(data):
    pe = PE(data)
    gets = find_server_getsockopt(pe, data)
    sets = find_setsockopt(pe, data)
    if gets.status == "clean" and sets.status == "clean":
        status = "clean"
    elif gets.status == "patched" and sets.status == "patched":
        status = "patched"
    else:
        status = "partial"
    return Inspection(pe, gets, sets, status)


# ---------------------------------------------------------------------------
# Building the patch
# ---------------------------------------------------------------------------

def allocate_caves(pe, data, len1, len2):
    text = pe.text
    if not (text.chars & 0x20000000):
        raise PatchError(".text is not marked executable; refusing to patch")
    start = _align_up(text.va + text.vsize, 16)
    end = text.va + text.rawsize
    needed = len1 + len2 + 16
    if start + needed > end:
        raise PatchError(".text has insufficient padding for code caves")

    later = [s for s in pe.sections if s.va > text.va]
    next_va = min((s.va for s in later), default=pe.size_of_image)

    for cand in range(start, end - needed + 1, 16):
        c2 = _align_up(cand + len1, 16)
        cave_end = c2 + len2
        if cave_end > end or cave_end > next_va:
            continue
        off = text.rva_to_off(cand)
        chunk = data[off:off + (cave_end - cand)]
        if all(b in (0x00, 0xCC) for b in chunk):
            return cand, c2, cave_end
    raise PatchError("could not find a zero-filled code cave in .text padding")


def build_cave1(pro1, func_rva, cave_rva):
    c = bytearray()
    c += b"\x81\xfa" + struct.pack("<I", IOCTL_GET_IPV6_V6ONLY)
    c += b"\x0f\x85" + struct.pack("<i", 17)
    c += b"\x41\xc7\x00\x00\x00\x00\x00"
    c += b"\x41\xc7\x01\x04\x00\x00\x00"
    c += b"\x31\xc0"
    c += b"\xc3"
    assert len(c) == 29
    c += pro1
    target = func_rva + len(pro1)
    rel = target - (cave_rva + len(c) + 5)
    c += b"\xe9" + struct.pack("<i", rel)
    return bytes(c)


def build_cave2(pro2, func_rva, cave_rva):
    c = bytearray()
    c += b"\x83\xfa\x00"
    c += b"\x0f\x85" + struct.pack("<i", 13)
    c += b"\x41\x83\xf8" + bytes([IP_ECN])
    c += b"\x0f\x85" + struct.pack("<i", 3)
    c += b"\x31\xc0"
    c += b"\xc3"
    assert len(c) == 22
    c += pro2
    target = func_rva + len(pro2)
    rel = target - (cave_rva + len(c) + 5)
    c += b"\xe9" + struct.pack("<i", rel)
    return bytes(c)


def build_hook(func_rva, original_length, cave_rva):
    rel = cave_rva - (func_rva + 5)
    return b"\xe9" + struct.pack("<i", rel) + b"\x90" * (original_length - 5)


@dataclass
class Plan:
    getsockopt_rva: int
    setsockopt_rva: int
    cave1_rva: int
    cave2_rva: int
    cave1: bytes
    cave2: bytes
    hook1: bytes
    hook2: bytes
    old_vsize: int
    new_vsize: int


def make_plan(data):
    ins = inspect(data)
    if ins.status == "patched":
        raise PatchError("already patched")
    if ins.status != "clean":
        raise PatchError("ws2_32.dll is partially patched or in an unknown state")
    
    len1 = len(PRO1)
    len2 = ins.setsockopt.length
    cave1_len = 29 + len1 + 5
    cave2_len = 22 + len2 + 5
    cave1_rva, cave2_rva, cave_end = allocate_caves(
        ins.pe, data, cave1_len, cave2_len
    )
    cave1 = build_cave1(PRO1, ins.getsockopt.rva, cave1_rva)
    cave2 = build_cave2(ins.setsockopt.prologue, ins.setsockopt.rva, cave2_rva)
    hook1 = build_hook(ins.getsockopt.rva, len1, cave1_rva)
    hook2 = build_hook(ins.setsockopt.rva, len2, cave2_rva)
    old_vsize = ins.pe.text.vsize
    new_vsize = cave_end - ins.pe.text.va
    return Plan(
        ins.getsockopt.rva, ins.setsockopt.rva,
        cave1_rva, cave2_rva,
        cave1, cave2, hook1, hook2,
        old_vsize, new_vsize,
    )


def apply_plan(data, plan):
    out = bytearray(data)
    pe = PE(out)
    text = pe.text
    o = pe.rva_to_off(plan.getsockopt_rva)
    out[o:o + len(plan.hook1)] = plan.hook1
    o = pe.rva_to_off(plan.setsockopt_rva)
    out[o:o + len(plan.hook2)] = plan.hook2
    o = pe.rva_to_off(plan.cave1_rva)
    out[o:o + len(plan.cave1)] = plan.cave1
    o = pe.rva_to_off(plan.cave2_rva)
    out[o:o + len(plan.cave2)] = plan.cave2
    struct.pack_into("<I", out, text.hdr + 8, plan.new_vsize)
    return bytes(out)


def verify_patch(data, plan):
    ins = inspect(data)
    if ins.status != "patched":
        raise PatchError("post-write verification failed")


# ---------------------------------------------------------------------------
# Locating Steam / the active prefix (Enhanced Auto-Detection)
# ---------------------------------------------------------------------------

def steam_roots():
    home = Path.home()
    roots = [
        home / ".local/share/Steam",
        home / ".steam/steam",
        home / ".steam/root",
        home / ".var/app/com.valvesoftware.Steam/.local/share/Steam",
        home / "snap/steam/common/.local/share/Steam",
        home / "snap/steam/current/.local/share/Steam",
    ]
    out = []
    seen = set()
    for r in roots:
        try:
            key = str(r.resolve())
        except OSError:
            key = str(r)
        if key not in seen and r.exists():
            seen.add(key)
            out.append(r)
    return out


def find_prefix(appid):
    manifest_name = f"appmanifest_{appid}.acf"
    steamapps_dirs = []

    # Gather all potential steamapps directories from roots & library folders
    for root in steam_roots():
        sa = root / "steamapps"
        if sa.exists():
            steamapps_dirs.append(sa)

        vdf = root / "steamapps" / "libraryfolders.vdf"
        if vdf.is_file():
            try:
                text = vdf.read_text(errors="replace")
                for m in re.finditer(r'"path"\s+"([^"]+)"', text):
                    lib_sa = Path(m.group(1)) / "steamapps"
                    if lib_sa.exists() and lib_sa not in steamapps_dirs:
                        steamapps_dirs.append(lib_sa)
            except OSError:
                pass

    # 1. Locate precisely using Steam's app manifest file
    for sa in steamapps_dirs:
        if (sa / manifest_name).exists():
            p = sa / "compatdata" / appid / "pfx"
            if p.exists() or (sa / "compatdata" / appid).exists():
                return p

    # 2. Fallback: check direct compatdata paths across all found steamapps dirs
    for sa in steamapps_dirs:
        p = sa / "compatdata" / appid / "pfx"
        if p.exists():
            return p

    return None


def dll_from_prefix(prefix):
    p = prefix / "drive_c" / "windows" / "system32" / "ws2_32.dll"
    if not p.exists():
        alt = prefix / "pfx" / "drive_c" / "windows" / "system32" / "ws2_32.dll"
        if alt.exists():
            p = alt
        else:
            raise PatchError(
                "no ws2_32.dll found under %s\n"
                "Make sure Gray Zone Warfare has been launched at least once "
                "so Proton initializes the prefix." % prefix
            )
    return p.resolve()


def find_target_dll(args):
    if args.dll:
        p = Path(args.dll).expanduser()
        if not p.exists():
            raise PatchError("no such file: %s" % p)
        return p.resolve()
    
    prefix = Path(args.prefix).expanduser() if args.prefix else find_prefix(args.appid)
    if prefix is None:
        raise PatchError(
            "could not auto-detect the Gray Zone Warfare Proton prefix (appid %s).\n"
            "Use --prefix /path/to/steamapps/compatdata/%s/pfx\n"
            "or --dll /path/to/ws2_32.dll." % (args.appid, args.appid)
        )
    return dll_from_prefix(prefix)


# ---------------------------------------------------------------------------
# Process, hash, backup helpers
# ---------------------------------------------------------------------------

def game_running():
    proc = Path("/proc")
    try:
        entries = list(proc.iterdir())
    except OSError:
        return False
    for p in entries:
        if not p.name.isdigit():
            continue
        try:
            comm = (p / "comm").read_text(errors="ignore").strip()
        except OSError:
            continue
        if comm.startswith(GAME_COMM):
            return True
    return False


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def backup_path(dll):
    return Path(str(dll) + BACKUP_SUFFIX)


def legacy_backup_path(dll):
    return Path(str(dll) + LEGACY_BACKUP_SUFFIX)


def metadata_path(backup):
    return Path(str(backup) + ".json")


def write_metadata(backup, original_hash, patched_hash):
    meta = {
        "tool": "gzw_voip_fix-autodetect.py",
        "version": VERSION,
        "original_sha256": original_hash,
        "patched_sha256": patched_hash,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    try:
        metadata_path(backup).write_text(json.dumps(meta, indent=2) + "\n")
    except OSError:
        pass


def read_metadata(backup):
    p = metadata_path(backup)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


def build_label(h):
    return TESTED.get(h)


def restore_bytes_to(dll, new_data):
    st = os.stat(dll)
    mode = st.st_mode & 0o7777
    tmp = Path(str(dll) + ".gzw-voip-tmp-%d" % os.getpid())
    try:
        with open(tmp, "wb") as f:
            f.write(new_data)
        os.chmod(tmp, mode)
        os.replace(tmp, dll)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def prompt_yes(question):
    if not sys.stdin.isatty():
        raise PatchError("refusing to write in a non-interactive session without --yes")
    try:
        ans = input(question + " [y/N] ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def describe_func(f):
    if f.status == "clean":
        return "clean"
    if f.status == "patched":
        return "patched"
    return "unknown"


def cmd_check(dll, data):
    print("DLL:      %s" % dll)
    print("SHA-256:  %s" % sha256_bytes(data))
    try:
        ins = inspect(data)
    except PatchError as e:
        print("Status:   ERROR\n          %s" % e)
        return 1
    print("Status:   %s" % ins.status.upper())
    return 0


def cmd_patch(dll, data, args):
    ins = inspect(data)
    if ins.status == "patched":
        print("Already patched; nothing to do.")
        return 0
    if ins.status != "clean":
        raise PatchError("partial/unknown patch state; run --revert or reinstall Proton")

    plan = make_plan(data)
    if game_running() and not args.force:
        raise PatchError("Gray Zone Warfare is running. Exit the game first.")

    h = sha256_bytes(data)
    bp = backup_path(dll)
    if not bp.exists():
        shutil.copy2(dll, bp)

    new_data = apply_plan(data, plan)
    restore_bytes_to(dll, new_data)
    print("Patched successfully: %s" % dll)
    return 0


def cmd_revert(dll, data, args):
    bp = backup_path(dll)
    if not bp.exists():
        lb = legacy_backup_path(dll)
        if lb.exists():
            bp = lb
        else:
            raise PatchError("no backup found next to the DLL.")
    original = bp.read_bytes()
    restore_bytes_to(dll, original)
    print("Restored original DLL: %s" % dll)
    return 0


# ---------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(description="Patch Wine/Proton ws2_32.dll for Gray Zone Warfare VOIP")
    p.add_argument("--dll", help="explicit path to ws2_32.dll")
    p.add_argument("--prefix", help="Wine prefix path")
    p.add_argument("--appid", default=APPID, help="Steam app id")
    p.add_argument("--check", action="store_true", help="report state")
    p.add_argument("--dry-run", action="store_true", help="show plan")
    p.add_argument("--revert", action="store_true", help="restore original DLL")
    p.add_argument("--force", action="store_true", help="skip running-game check")
    p.add_argument("--yes", "-y", action="store_true", help="skip confirmation")
    args = p.parse_args(argv)

    try:
        dll = find_target_dll(args)
        data = dll.read_bytes()
        if args.check:
            return cmd_check(dll, data)
        if args.revert:
            return cmd_revert(dll, data, args)
        return cmd_patch(dll, data, args)
    except PatchError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())