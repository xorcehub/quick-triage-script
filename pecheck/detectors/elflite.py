"""Minimal ELF triage (struct-only): arch/type line, packed-section marker,
interpreter, linux-specific symbol hints. Full symbol/import walks are the
RE project's job - this is quick context."""
import struct

from ..model import Finding, CRITICAL

_MACH = {0x03: "x86", 0x3E: "x86-64", 0xB7: "aarch64", 0xF3: "riscv64",
         0x08: "mips", 0x28: "arm", 0x32: "ppc64le"}
_TYPE = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}


def _sections(raw):
    """>> (machine, etype, [section names]) or None."""
    if len(raw) < 64 or raw[:4] != b"\x7fELF":
        return None
    ei_class, ei_data = raw[4], raw[5]
    fmt = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2
    if is64:
        e_type, e_machine = struct.unpack_from(fmt + "HH", raw, 16)
        e_shoff, = struct.unpack_from(fmt + "Q", raw, 40)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(fmt + "HHH", raw, 58)
    else:
        e_type, e_machine = struct.unpack_from(fmt + "HH", raw, 16)
        e_shoff, = struct.unpack_from(fmt + "I", raw, 32)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(fmt + "HHH", raw, 46)
    if not e_shoff or not e_shnum or e_shoff > len(raw):
        return e_machine, e_type, []
    ents = []
    for i in range(min(e_shnum, 96)):  # ponytail: 96-section cap, fuzzed headers
        off = e_shoff + i * e_shentsize
        if off + e_shentsize > len(raw):
            break
        sh_name, = struct.unpack_from(fmt + "I", raw, off)
        if is64:  # Elf64_Shdr: sh_offset@24, sh_size@32
            sh_offset, sh_size = struct.unpack_from(fmt + "QQ", raw, off + 24)
        else:     # Elf32_Shdr: sh_offset@16, sh_size@20
            sh_offset, sh_size = struct.unpack_from(fmt + "II", raw, off + 16)
        ents.append((sh_name, sh_offset, sh_size))
    # section-name string table
    if e_shstrndx < len(ents):
        sn, so, ss = ents[e_shstrndx]
        table = raw[so:so + ss] if so < len(raw) else b""
        names = []
        for n, _, _ in ents:
            if n >= len(table):
                names.append("")
                continue
            q = table.find(b"\x00", n)
            names.append(table[n:q if q >= 0 else len(table)].decode(errors="replace"))
        return e_machine, e_type, names
    return e_machine, e_type, []


def run(t):
    if not t.raw or t.kind != "ELF":
        return []
    out = []
    got = _sections(t.raw)
    if got is None:
        return [Finding("STRUCT?", "ELF header unreadable")]
    mach, etype, names = got
    arch = _MACH.get(mach, hex(mach))
    ty = _TYPE.get(etype, str(etype))
    line = f"ELF {arch} {ty}"
    if b"/ld-linux" in t.raw[:262144] or b"/lib/ld" in t.raw[:262144]:
        line += " dynamic"
    out.append(Finding("NOTE", line))
    low = [n.lower() for n in names if n]
    if any("upx" in n for n in low) or b"UPX!" in t.raw[:262144]:
        out.append(Finding("PACKED?", "UPX-packed ELF (UPX! marker)", CRITICAL))
    # symbol-table hints (unstripped binaries leak intent in names)
    for sym, note in ((b"ptrace", "anti-debug/debugger primitive"),
                      (b"process_vm_writev", "cross-process memory write"),
                      (b"dlopen", "runtime library loading")):
        if sym in t.raw[:4 << 20]:
            out.append(Finding("MEM?", f"symbol/string {sym.decode()}: {note}"))
            break  # one hint is enough context; deep dives belong to the RE project
    return out
