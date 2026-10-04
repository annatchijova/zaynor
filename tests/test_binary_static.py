import hashlib
import json
import random
import struct
import subprocess
import sys

import pytest

from tools.binary_static import (
    OfflineEvidenceError,
    combine_staged_evidence,
    freeze_staged_evidence,
    import_binary_static,
    triage_bytes,
)
from tools.binary_static.measure import byte_histogram, extract_strings, shannon_entropy
from tools.freebsd_evidence import import_freebsd_evidence
from tools.offline_evidence import validate_package_context
from zaynor.frozen_snapshot import materialize_frozen_snapshot

# --- synthetic ELF / PE builders ----------------------------------------------
#
# Fixtures are built in-test so the suite commits no third-party binaries and
# every byte under test is deliberate.

SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_DYNAMIC, SHT_NOTE, SHT_NOBITS = 1, 2, 3, 6, 7, 8
SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 0x1, 0x2, 0x4


def build_elf(
    sections,
    *,
    is64=True,
    little=True,
    e_type=1,
    machine=62,
    osabi=9,
    segments=(),
    load_base=None,
    entry=0,
):
    """Lay out a well-formed ELF image; returns (bytes, layout by section name)."""
    endian = "<" if little else ">"
    ehsize, phentsize, shentsize = (64, 56, 64) if is64 else (52, 32, 40)
    all_sections = [{"name": "", "type": 0}, *sections, {"name": ".shstrtab", "type": SHT_STRTAB}]
    names = b"\x00"
    name_offsets = {}
    for section in all_sections[1:]:
        name_offsets[section["name"]] = len(names)
        names += section["name"].encode() + b"\x00"
    all_sections[-1]["data"] = names
    index_of = {section["name"]: index for index, section in enumerate(all_sections)}

    position = ehsize + len(segments) * phentsize
    body = bytearray()
    layout = {}
    for index, section in enumerate(all_sections):
        if index == 0:
            continue
        align = section.get("addralign", 1) or 1
        pad = (-position) % align
        body += b"\x00" * pad
        position += pad
        if section["type"] == SHT_NOBITS:
            offset, size = position, section.get("nobits_size", 0)
        else:
            offset, size = position, len(section.get("data", b""))
            body += section.get("data", b"")
            position += size
        addr = 0
        if load_base is not None and section.get("flags", 0) & SHF_ALLOC:
            addr = load_base + offset
        layout[section["name"]] = {"index": index, "offset": offset, "size": size, "addr": addr}
    pad = (-position) % 8
    body += b"\x00" * pad
    position += pad
    shoff = position
    total = shoff + len(all_sections) * shentsize

    section_table = bytearray()
    for index, section in enumerate(all_sections):
        if index == 0:
            section_table += b"\x00" * shentsize
            continue
        entry_layout = layout[section["name"]]
        link = section.get("link", 0)
        if isinstance(link, str):
            link = index_of[link]
        values = (
            name_offsets[section["name"]], section["type"], section.get("flags", 0),
            entry_layout["addr"], entry_layout["offset"], entry_layout["size"], link,
            section.get("info", 0), section.get("addralign", 1), section.get("entsize", 0),
        )
        fmt = "IIQQQQIIQQ" if is64 else "IIIIIIIIII"
        section_table += struct.pack(endian + fmt, *values)

    program_table = bytearray()
    for segment in segments:
        if segment.get("whole_file"):
            offset, size = 0, total
        else:
            offset, size = layout[segment["section"]]["offset"], layout[segment["section"]]["size"]
        vaddr = (load_base or 0) + offset
        if is64:
            program_table += struct.pack(
                endian + "IIQQQQQQ", segment["type"], segment.get("flags", 4), offset, vaddr,
                vaddr, size, size, segment.get("align", 1),
            )
        else:
            program_table += struct.pack(
                endian + "IIIIIIII", segment["type"], offset, vaddr, vaddr, size, size,
                segment.get("flags", 4), segment.get("align", 1),
            )

    ident = b"\x7fELF" + bytes([2 if is64 else 1, 1 if little else 2, 1, osabi, 0]) + b"\x00" * 7
    header_fmt = "HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH"
    header = ident + struct.pack(
        endian + header_fmt, e_type, machine, 1, entry, ehsize if segments else 0, shoff, 0,
        ehsize, phentsize if segments else 0, len(segments), shentsize, len(all_sections),
        len(all_sections) - 1,
    )
    image = bytes(header + program_table + body + section_table)
    assert len(image) == total
    return image, layout


def strtab(*names):
    data = b"\x00"
    offsets = {}
    for name in names:
        offsets[name] = len(data)
        data += name.encode() + b"\x00"
    return data, offsets


def symtab64(entries, offsets, *, endian="<"):
    data = b"\x00" * 24
    for name, bind, sym_type, shndx, value, size in entries:
        data += struct.pack(
            endian + "IBBHQQ", offsets[name], (bind << 4) | sym_type, 0, shndx, value, size
        )
    return data


def freebsd_note(endian="<"):
    header = struct.pack(endian + "III", 8, 4, 1)
    return header + b"FreeBSD\x00" + struct.pack(endian + "I", 1403000)


def freebsd_kernel_module():
    """ELF64 ET_REL, FreeBSD OSABI: the shape of a /boot/kernel/*.ko file."""
    names, offsets = strtab("if_test.c", "helper", "test_modevent", "printf", "malloc")
    symbols = symtab64(
        [
            ("if_test.c", 0, 4, 0xFFF1, 0, 0),
            ("helper", 0, 2, 1, 0x10, 8),
            ("test_modevent", 1, 2, 1, 0x20, 32),
            ("printf", 1, 0, 0, 0, 0),
            ("malloc", 1, 0, 0, 0, 0),
        ],
        offsets,
    )
    return build_elf(
        [
            {"name": ".text", "type": SHT_PROGBITS, "flags": SHF_ALLOC | SHF_EXECINSTR,
             "data": b"\x90" * 32 + b"ZAYNOR_MARKER" + bytes(range(64)), "addralign": 16},
            {"name": ".data", "type": SHT_PROGBITS, "flags": SHF_ALLOC | SHF_WRITE,
             "data": b"\x00" * 16, "addralign": 8},
            {"name": ".bss", "type": SHT_NOBITS, "flags": SHF_ALLOC | SHF_WRITE,
             "nobits_size": 4096, "addralign": 8},
            {"name": ".note.tag", "type": SHT_NOTE, "flags": SHF_ALLOC, "data": freebsd_note(),
             "addralign": 4},
            {"name": ".comment", "type": SHT_PROGBITS,
             "data": b"\x00FreeBSD clang version 18.1.6\x00"},
            {"name": ".symtab", "type": SHT_SYMTAB, "data": symbols, "link": ".strtab", "info": 3,
             "addralign": 8, "entsize": 24},
            {"name": ".strtab", "type": SHT_STRTAB, "data": names},
        ]
    )[0]


def dynamic_executable():
    dynstr, offsets = strtab("libc.so.7", "libthr.so.3")
    interp = b"/libexec/ld-elf.so.1\x00"

    def sections(dynamic_data):
        return [
            {"name": ".interp", "type": SHT_PROGBITS, "flags": SHF_ALLOC, "data": interp},
            {"name": ".dynstr", "type": SHT_STRTAB, "flags": SHF_ALLOC, "data": dynstr},
            {"name": ".dynamic", "type": SHT_DYNAMIC, "flags": SHF_ALLOC | SHF_WRITE,
             "data": dynamic_data, "link": ".dynstr", "addralign": 8, "entsize": 16},
        ]

    segments = (
        {"type": 1, "whole_file": True, "flags": 5},
        {"type": 3, "section": ".interp"},
        {"type": 2, "section": ".dynamic", "flags": 6},
    )
    placeholder = b"\x00" * 16 * 5
    _, layout = build_elf(sections(placeholder), e_type=3, segments=segments, load_base=0x400000)
    dynamic = b"".join(
        struct.pack("<qQ", tag, value)
        for tag, value in (
            (1, offsets["libc.so.7"]),
            (1, offsets["libthr.so.3"]),
            (5, layout[".dynstr"]["addr"]),
            (10, layout[".dynstr"]["size"]),
            (0, 0),
        )
    )
    image, _ = build_elf(sections(dynamic), e_type=3, segments=segments, load_base=0x400000)
    return image


def build_pe(*, plus=True, subsystem=10, machine=0x8664, with_certificate=True):
    """Minimal PE image: DOS header, COFF, optional header, two sections."""
    e_lfanew = 0x40
    layout = struct.Struct(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII" if plus else "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII"
    )
    size_of_optional = layout.size + 16 * 8
    header_end = e_lfanew + 4 + 20 + size_of_optional + 2 * 40
    text_offset, data_offset = 0x200, 0x400
    text = b"\xcc" * 0x200
    data = b"ZAYNOR_MARKER".ljust(0x200, b"\x00")
    certificate = struct.pack("<IHH", 72, 0x0200, 2) + b"\x30\x82" + b"\x00" * 62
    certificate_offset = 0x600
    if plus:
        optional = layout.pack(0x20B, 14, 0, 0x200, 0x200, 0, 0x1000, 0x1000, 0x10000000,
                               0x1000, 0x200, 0, 0, 0, 0, 0, 0, 0, 0x3000, 0x200, 0,
                               subsystem, 0x0160, 0, 0, 0, 0, 0, 16)
    else:
        optional = layout.pack(0x10B, 14, 0, 0x200, 0x200, 0, 0x1000, 0x1000, 0x2000,
                               0x400000, 0x1000, 0x200, 0, 0, 0, 0, 0, 0, 0, 0x3000, 0x200,
                               0, subsystem, 0x0140, 0, 0, 0, 0, 0, 16)
    directories = [(0, 0)] * 16
    if with_certificate:
        directories[4] = (certificate_offset, len(certificate))
    optional += b"".join(struct.pack("<II", *pair) for pair in directories)
    coff = struct.pack("<HHIIIHH", machine, 2, 0, 0, 0, size_of_optional, 0x0022)
    section_table = struct.pack("<8sIIIIIIHHI", b".text", 0x200, 0x1000, 0x200, text_offset,
                                0, 0, 0, 0, 0x60000020)
    section_table += struct.pack("<8sIIIIIIHHI", b".data", 0x200, 0x2000, 0x200, data_offset,
                                 0, 0, 0, 0, 0xC0000040)
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", e_lfanew)
    headers = dos + b"PE\x00\x00" + coff + optional + section_table
    assert len(headers) == header_end
    image = headers.ljust(text_offset, b"\x00") + text + data
    if with_certificate:
        image = image.ljust(certificate_offset, b"\x00") + certificate
    return image


def _rol32(value, bits):
    bits %= 32
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF if bits else value


def _literal_checksum(data, offset):
    """CheckSumMappedFile, word by word, independent of the module under test."""
    buffer = bytearray(data)
    buffer[offset : offset + 4] = b"\x00" * 4
    if len(buffer) % 2:
        buffer += b"\x00"
    total = 0
    for index in range(0, len(buffer), 2):
        total += buffer[index] | (buffer[index + 1] << 8)
        total = (total & 0xFFFF) + (total >> 16)
    return (total + len(data)) & 0xFFFFFFFF


def _vs_node(key, value=b"", children=(), *, value_type=0, value_length=None):
    """One VS_VERSIONINFO node; children are padded to 4 bytes."""
    key_bytes = (key + "\x00").encode("utf-16-le")
    head = 6 + len(key_bytes)
    head_pad = (-head) % 4
    value_pad = (-(head + head_pad + len(value))) % 4 if children else 0
    kids = b"".join(child + b"\x00" * ((-len(child)) % 4) for child in children)
    total = head + head_pad + len(value) + value_pad + len(kids)
    length = len(value) if value_length is None else value_length
    return (
        struct.pack("<HHH", total, length, value_type) + key_bytes + b"\x00" * head_pad
        + value + b"\x00" * value_pad + kids
    )


VERSION_STRINGS = (
    ("CompanyName", "Demo Corp"),
    ("FileDescription", "Demo DLL"),
    ("FileVersion", "1.2.3.4"),
    ("OriginalFilename", "demo.dll"),
)


def _version_resource():
    strings = [
        _vs_node(key, (text + "\x00").encode("utf-16-le"), value_type=1,
                 value_length=len(text) + 1)
        for key, text in VERSION_STRINGS
    ]
    table = _vs_node("040904B0", children=strings, value_type=1)
    string_info = _vs_node("StringFileInfo", children=[table], value_type=1)
    translation = _vs_node("Translation", struct.pack("<HH", 0x0409, 0x04B0))
    var_info = _vs_node("VarFileInfo", children=[translation], value_type=1)
    fixed = struct.pack(
        "<13I", 0xFEEF04BD, 0x00010000, (1 << 16) | 2, (3 << 16) | 4, (1 << 16) | 2,
        (3 << 16) | 4, 0x3F, 0, 0x40004, 2, 0, 0, 0,
    )
    return _vs_node("VS_VERSION_INFO", fixed, children=[string_info, var_info])


class _Blob:
    """Section contents addressed by RVA while they are laid out."""

    def __init__(self, rva):
        self.rva = rva
        self.data = bytearray()

    def put(self, payload, align=8):
        while len(self.data) % align:
            self.data += b"\x00"
        rva = self.rva + len(self.data)
        self.data += payload
        return rva

    def patch(self, rva, payload):
        start = rva - self.rva
        self.data[start : start + len(payload)] = payload


RICH_ENTRIES = ((0x0104, 30148, 10), (0x0105, 30148, 3), (0x00FF, 30148, 1))
PDB_PATH = "C:\\build\\demo\\x64\\Release\\demo.pdb"
IMAGE_BASE = 0x180000000


def build_pe_rich():
    """PE32+ DLL with every structure the Windows triage reads."""
    e_lfanew, rdata_rva, rdata_raw, rsrc_rva = 0xB0, 0x2000, 0x600, 0x4000
    rdata = _Blob(rdata_rva)
    kernel32 = rdata.put(b"KERNEL32.dll\x00")
    ws2 = rdata.put(b"WS2_32.dll\x00")
    create_file = rdata.put(struct.pack("<H", 0xC4) + b"CreateFileW\x00", align=2)
    sleep = rdata.put(struct.pack("<H", 0x5A) + b"Sleep\x00", align=2)
    ilt1 = rdata.put(struct.pack("<QQQ", create_file, sleep, 0))
    iat1 = rdata.put(struct.pack("<QQQ", create_file, sleep, 0))
    ilt2 = rdata.put(struct.pack("<QQ", (1 << 63) | 23, 0))
    iat2 = rdata.put(struct.pack("<QQ", (1 << 63) | 23, 0))
    imports = rdata.put(
        struct.pack("<5I", ilt1, 0, 0, kernel32, iat1)
        + struct.pack("<5I", ilt2, 0, 0, ws2, iat2) + b"\x00" * 20,
        align=4,
    )
    user32 = rdata.put(b"USER32.dll\x00")
    message_box = rdata.put(struct.pack("<H", 0) + b"MessageBoxW\x00", align=2)
    delay_int = rdata.put(struct.pack("<QQ", message_box, 0))
    delay_iat = rdata.put(struct.pack("<QQ", 0, 0))
    delay_module = rdata.put(struct.pack("<Q", 0))
    delay = rdata.put(
        struct.pack("<8I", 1, user32, delay_module, delay_iat, delay_int, 0, 0, 0)
        + b"\x00" * 32,
        align=4,
    )
    export_dir = rdata.put(b"\x00" * 40, align=4)
    dll_name = rdata.put(b"demo.dll\x00", align=1)
    name1 = rdata.put(b"DemoExport\x00", align=1)
    name2 = rdata.put(b"DemoForward\x00", align=1)
    forwarder = rdata.put(b"NTDLL.RtlAllocateHeap\x00", align=1)
    functions = rdata.put(struct.pack("<III", 0x1010, forwarder, 0x1020), align=4)
    names = rdata.put(struct.pack("<II", name1, name2), align=4)
    ordinals = rdata.put(struct.pack("<HH", 0, 1), align=2)
    export_end = rdata.rva + len(rdata.data)
    rdata.patch(export_dir, struct.pack("<IIHHIIIIIII", 0, 0, 0, 0, dll_name, 1, 3, 2,
                                        functions, names, ordinals))
    codeview = b"RSDS" + bytes(range(16)) + struct.pack("<I", 3) + PDB_PATH.encode() + b"\x00"
    codeview_rva = rdata.put(codeview, align=4)
    debug = rdata.put(
        struct.pack("<IIHHIIII", 0, 0x5F3E2A10, 0, 0, 2, len(codeview), codeview_rva,
                    rdata_raw + (codeview_rva - rdata_rva))
        + struct.pack("<IIHHIIII", 0, 0, 0, 0, 16, 0, 0, 0),
        align=4,
    )
    callbacks = rdata.put(struct.pack("<QQQ", IMAGE_BASE + 0x1030, IMAGE_BASE + 0x1040, 0))
    tls_index = rdata.put(struct.pack("<I", 0), align=4)
    tls = rdata.put(struct.pack("<QQQQII", IMAGE_BASE + 0x3000, IMAGE_BASE + 0x3008,
                                IMAGE_BASE + tls_index, IMAGE_BASE + callbacks, 0, 0))
    assert len(rdata.data) <= 0x600

    version = _version_resource()
    rcdata = bytes(range(64))

    def directory(entries):
        return struct.pack("<IIHHHH", 0, 0, 0, 0, 0, len(entries)) + b"".join(
            struct.pack("<II", ident, target) for ident, target in entries
        )

    subdirectory = 0x80000000
    rsrc = (
        directory([(10, subdirectory | 0x20), (16, subdirectory | 0x38)])  # 0x00 types
        + directory([(101, subdirectory | 0x50)])  # 0x20 RCDATA names
        + directory([(1, subdirectory | 0x68)])  # 0x38 VERSION names
        + directory([(0x409, 0x80)])  # 0x50 RCDATA languages
        + directory([(0x409, 0x90)])  # 0x68 VERSION languages
        + struct.pack("<IIII", rsrc_rva + 0xA0, len(rcdata), 0, 0)  # 0x80
        + struct.pack("<IIII", rsrc_rva + 0xE0, len(version), 0, 0)  # 0x90
        + rcdata  # 0xA0
        + version  # 0xE0
    )
    assert len(rsrc) <= 0x400
    data_section = (
        b"https://updates.example.invalid/check\x00\x00"
        + "Software\\Demo\\Settings".encode("utf-16-le") + b"\x00\x00"
    ).ljust(0x200, b"\x00")
    sections = [
        (b".text", 0x1000, 0x400, 0x200, 0x60000020, b"\xcc" * 0x200),
        (b".rdata", rdata_rva, rdata_raw, 0x600, 0x40000040,
         bytes(rdata.data).ljust(0x600, b"\x00")),
        (b".data", 0x3000, 0xC00, 0x200, 0xC0000040, data_section),
        (b".rsrc", rsrc_rva, 0xE00, 0x400, 0x40000040, rsrc.ljust(0x400, b"\x00")),
    ]
    overlay = b"OVERLAY!" * 32
    certificate = struct.pack("<IHH", 72, 0x0200, 2) + b"\x30\x82" + b"\x00" * 62
    certificate_offset = 0x1200 + len(overlay)
    directories = [(0, 0)] * 16
    directories[0] = (export_dir, export_end - export_dir)
    directories[1] = (imports, 60)
    directories[2] = (rsrc_rva, len(rsrc))
    directories[4] = (certificate_offset, len(certificate))
    directories[6] = (debug, 56)
    directories[9] = (tls, 40)
    directories[13] = (delay, 64)

    dos = bytearray(b"MZ" + b"\x00" * 0x3A + struct.pack("<I", e_lfanew))
    dos += b"\x00" * (0x80 - len(dos))
    stub = b"This program cannot be run in DOS mode.\r\r\n$"
    dos[0x4E : 0x4E + len(stub)] = stub
    key = 0x80
    for index in range(0x80):
        if not 0x3C <= index < 0x40:
            key = (key + _rol32(dos[index], index)) & 0xFFFFFFFF
    for product, build, count in RICH_ENTRIES:
        key = (key + _rol32((product << 16) | build, count)) & 0xFFFFFFFF
    rich = struct.pack("<IIII", 0x536E6144 ^ key, key, key, key)
    for product, build, count in RICH_ENTRIES:
        rich += struct.pack("<II", ((product << 16) | build) ^ key, count ^ key)
    rich += b"Rich" + struct.pack("<I", key)
    assert 0x80 + len(rich) == e_lfanew

    optional = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 14, 30, 0x200, 0x800, 0, 0x1000, 0x1000,
        IMAGE_BASE, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x5000, 0x400, 0, 3, 0x0160,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    ) + b"".join(struct.pack("<II", *pair) for pair in directories)
    coff = struct.pack("<HHIIIHH", 0x8664, len(sections), 0x5F3E2A10, 0, 0, len(optional),
                       0x2022)
    table = b"".join(
        struct.pack("<8sIIIIIIHHI", name, raw_size, rva, raw_size, raw, 0, 0, 0, 0, flags)
        for name, rva, raw, raw_size, flags, _ in sections
    )
    image = bytearray((bytes(dos) + rich + b"PE\x00\x00" + coff + optional + table)
                      .ljust(0x400, b"\x00"))
    for _, _, raw, _, _, content in sections:
        assert len(image) == raw
        image += content
    image += overlay + certificate
    checksum_offset = e_lfanew + 24 + 64
    struct.pack_into("<I", image, checksum_offset, _literal_checksum(bytes(image), checksum_offset))
    return bytes(image)


def linux_kernel_module():
    """ELF64 ET_REL in the shape of a Linux .ko: .modinfo and a GNU build-id."""
    modinfo = (
        b"license=GPL\x00author=Lab\x00description=demo module\x00"
        b"vermagic=6.8.0-45-generic SMP preempt mod_unload modversions \x00"
        b"name=demo_mod\x00depends=\x00"
    )
    build_id = struct.pack("<III", 4, 20, 3) + b"GNU\x00" + bytes(range(20))
    names, offsets = strtab("init_module", "printk")
    symbols = symtab64(
        [("init_module", 1, 2, 1, 0, 16), ("printk", 1, 0, 0, 0, 0)], offsets
    )
    return build_elf(
        [
            {"name": ".text", "type": SHT_PROGBITS, "flags": SHF_ALLOC | SHF_EXECINSTR,
             "data": b"\xc3" * 16, "addralign": 16},
            {"name": ".modinfo", "type": SHT_PROGBITS, "flags": SHF_ALLOC, "data": modinfo},
            {"name": ".note.gnu.build-id", "type": SHT_NOTE, "flags": SHF_ALLOC,
             "data": build_id, "addralign": 4},
            {"name": ".symtab", "type": SHT_SYMTAB, "data": symbols, "link": ".strtab",
             "info": 1, "addralign": 8, "entsize": 24},
            {"name": ".strtab", "type": SHT_STRTAB, "data": names},
        ],
        osabi=0,
    )[0]


def linux_executable():
    """ELF64 ET_DYN for Linux: interpreter, DT_NEEDED, GNU version needs, ABI tag."""
    dynstr, offsets = strtab("libc.so.6", "GLIBC_2.34", "GLIBC_2.2.5")
    verneed = (
        struct.pack("<HHIII", 1, 2, offsets["libc.so.6"], 16, 0)
        + struct.pack("<IHHII", 0x069691B4, 0, 3, offsets["GLIBC_2.34"], 16)
        + struct.pack("<IHHII", 0x09691A75, 0, 2, offsets["GLIBC_2.2.5"], 0)
    )
    abi_tag = struct.pack("<III", 4, 16, 1) + b"GNU\x00" + struct.pack("<IIII", 0, 3, 2, 0)

    def sections(dynamic_data):
        return [
            {"name": ".interp", "type": SHT_PROGBITS, "flags": SHF_ALLOC,
             "data": b"/lib64/ld-linux-x86-64.so.2\x00"},
            {"name": ".note.ABI-tag", "type": SHT_NOTE, "flags": SHF_ALLOC, "data": abi_tag,
             "addralign": 4},
            {"name": ".dynstr", "type": SHT_STRTAB, "flags": SHF_ALLOC, "data": dynstr},
            {"name": ".gnu.version_r", "type": 0x6FFFFFFE, "flags": SHF_ALLOC, "data": verneed,
             "link": ".dynstr", "info": 1, "addralign": 8},
            {"name": ".text", "type": SHT_PROGBITS, "flags": SHF_ALLOC | SHF_EXECINSTR,
             "data": b"\x90" * 32, "addralign": 16},
            {"name": ".dynamic", "type": SHT_DYNAMIC, "flags": SHF_ALLOC | SHF_WRITE,
             "data": dynamic_data, "link": ".dynstr", "addralign": 8, "entsize": 16},
        ]

    segments = (
        {"type": 1, "whole_file": True, "flags": 5},
        {"type": 3, "section": ".interp"},
        {"type": 2, "section": ".dynamic", "flags": 6},
    )
    options = {"e_type": 3, "osabi": 0, "segments": segments, "load_base": 0x400000}
    _, layout = build_elf(sections(b"\x00" * 16 * 4), **options)
    dynamic = b"".join(
        struct.pack("<qQ", tag, value)
        for tag, value in (
            (1, offsets["libc.so.6"]),
            (5, layout[".dynstr"]["addr"]),
            (10, layout[".dynstr"]["size"]),
            (0, 0),
        )
    )
    return build_elf(sections(dynamic), entry=layout[".text"]["addr"] + 4, **options)


TARGETS = {
    "FreeBSD": {"os": "FreeBSD", "release": "14.3-RELEASE", "arch": "amd64",
                "kernel_build": "GENERIC-14.3-p1"},
    "Linux": {"os": "Linux", "release": "Ubuntu 24.04.1 LTS", "arch": "x86_64",
              "kernel_build": "6.8.0-45-generic"},
    "Windows": {"os": "Windows", "release": "Windows 11 23H2", "arch": "AMD64",
                "kernel_build": "22631.4317"},
}


# --- package helpers ---------------------------------------------------------


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _package(binaries, signatures=None, *, module="binary_static"):
    package = {
        "schema_version": 1,
        "module": module,
        "case_id": "INC-BINARY-001",
        "target": {
            "os": "FreeBSD",
            "release": "14.3-RELEASE",
            "arch": "amd64",
            "kernel_build": "GENERIC-14.3-p1",
        },
        "acquisition": {
            "acquisition_id": "acq-external-disk-001",
            "vantage": "external_disk",
            "lineage_id": "lineage:disk-capture-001",
            "captured_at": "2026-09-30T12:00:00Z",
            "capture_time_source": "hypervisor-record",
        },
        "binaries": binaries,
    }
    if signatures is not None:
        package["signatures"] = signatures
    return package


def _write(source, relative, data):
    path = source / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"source_path": relative, "sha256": _sha256(data)}


def _binary(source, relative, data, *, logical_path, declared_kind):
    return {
        "logical_path": logical_path,
        "declared_kind": declared_kind,
        **_write(source, relative, data),
    }


def _observations(staging_root, module="binary_static"):
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((staging_root / "observations" / module).glob("*.json"))
    ]


def _triage(staged, index=0):
    return next(
        item
        for item in _observations(staged.staging_root)
        if item["observation_id"] == f"binary_static:{index:06d}:triage"
    )


# --- tests -------------------------------------------------------------------


def test_kernel_module_triage_stages_original_and_freezes(tmp_path):
    source = tmp_path / "source"
    image = freebsd_kernel_module()
    binaries = [
        _binary(source, "files/boot/kernel/if_test.ko", image,
                logical_path="/boot/kernel/if_test.ko", declared_kind="kernel_module")
    ]

    staged = import_binary_static(_package(binaries), source, tmp_path / "staging")

    assert staged.analysis_status == "analysis_unsupported"
    assert staged.observation_count == 1
    assert {
        "vigia_input_contract_not_validated",
        "static_triage_only_no_disassembly_no_execution",
        "file_presence_does_not_establish_execution",
        "kernel_module_load_state_unknown",
        "signature_matching_not_performed",
    } <= set(staged.limitations)
    observation = _triage(staged)
    fields = observation["fields"]
    assert observation["kind"] == "binary_triage"
    assert observation["status"] == "observed"
    assert observation["source"]["sha256"] == fields["content_sha256"] == _sha256(image)
    assert observation["source"]["lineage_id"] == "lineage:disk-capture-001"
    assert fields["format"] == "elf"
    assert fields["parse_issues"] == []
    assert sum(fields["byte_histogram"]) == fields["size_bytes"] == len(image)
    elf = fields["elf"]
    assert elf["ident"]["osabi_name"] == "FREEBSD"
    assert elf["header"]["type_name"] == "REL"
    assert elf["header"]["machine_name"] == "X86_64"
    assert [section["name"] for section in elf["sections"]] == [
        "", ".text", ".data", ".bss", ".note.tag", ".comment", ".symtab", ".strtab", ".shstrtab"
    ]
    bss = elf["sections"][3]
    assert bss["type_name"] == "NOBITS" and bss["sha256"] is None
    text = elf["sections"][1]
    assert text["flag_names"]["names"] == ["ALLOC", "EXECINSTR"]
    assert text["sha256"] is not None and text["entropy_bits_per_byte"] is not None
    (table,) = elf["symbol_tables"]
    assert table["entry_count"] == 6
    assert table["bind_counts"] == {"LOCAL": 3, "GLOBAL": 3}
    assert table["undefined_count"] == 2
    assert [(s["name"], s["undefined"]) for s in table["symbols"]] == [
        ("test_modevent", False), ("printf", True), ("malloc", True)
    ]
    (note,) = elf["notes"]
    assert note["owner"] == "FreeBSD" and note["freebsd_abi_tag"] == 1403000
    assert elf["comment"] == [{"name": "FreeBSD clang version 18.1.6"}]
    assert elf["interpreter"] is None and elf["dynamic"] is None

    manifest, evidence_dir = freeze_staged_evidence(staged, tmp_path / "cases")
    frozen_paths = {entry.relative_path for entry in manifest.entries}
    assert "originals/binary_static/files/boot/kernel/if_test.ko" in frozen_paths
    assert "metadata/binary_static-input-package.json" in frozen_paths
    with materialize_frozen_snapshot(manifest, evidence_dir) as snapshot:
        frozen = snapshot.path / "originals/binary_static/files/boot/kernel/if_test.ko"
        assert frozen.read_bytes() == image


def test_elf32_big_endian_is_parsed_with_its_own_byte_order():
    names, offsets = strtab("entry_point")
    symbols = b"\x00" * 16 + struct.pack(">IIIBBH", offsets["entry_point"], 0x100, 4, 0x12, 0, 1)
    image, _ = build_elf(
        [
            {"name": ".text", "type": SHT_PROGBITS, "flags": SHF_ALLOC | SHF_EXECINSTR,
             "data": b"\x60\x00\x00\x00" * 4, "addralign": 4},
            {"name": ".symtab", "type": SHT_SYMTAB, "data": symbols, "link": ".strtab", "info": 1,
             "addralign": 4, "entsize": 16},
            {"name": ".strtab", "type": SHT_STRTAB, "data": names},
        ],
        is64=False, little=False, e_type=2, machine=20, osabi=0, entry=0x100,
    )

    status, fields, codes = triage_bytes(image)

    assert status == "observed" and codes == []
    elf = fields["elf"]
    assert elf["ident"] == {
        "class": 32, "data": "big", "version": 1, "osabi": 0, "osabi_name": "SYSV",
        "abiversion": 0,
    }
    assert elf["header"]["machine_name"] == "PPC" and elf["header"]["entry"] == 0x100
    (table,) = elf["symbol_tables"]
    assert table["symbols"][0]["name"] == "entry_point"
    assert table["symbols"][0]["type_name"] == "FUNC"


def test_dynamic_executable_records_interpreter_and_needed_through_segments():
    status, fields, _ = triage_bytes(dynamic_executable())

    assert status == "observed"
    elf = fields["elf"]
    assert elf["interpreter"] == {"name": "/libexec/ld-elf.so.1"}
    assert [entry["name"] for entry in elf["dynamic"]["needed"]] == ["libc.so.7", "libthr.so.3"]
    assert elf["dynamic"]["source"].startswith("segment:")
    load = next(segment for segment in elf["segments"] if segment["type_name"] == "LOAD")
    assert load["flag_names"]["names"] == ["R", "X"] and load["sha256"] is not None


def test_pe32_plus_efi_application_reports_certificate_presence_without_verifying(tmp_path):
    source = tmp_path / "source"
    image = build_pe()
    binaries = [
        _binary(source, "files/boot/loader.efi", image,
                logical_path="/boot/loader.efi", declared_kind="boot_file")
    ]

    staged = import_binary_static(_package(binaries), source, tmp_path / "staging")

    fields = _triage(staged)["fields"]
    assert fields["format"] == "pe"
    pe = fields["pe"]
    assert pe["optional"]["format"] == "PE32+"
    assert pe["optional"]["subsystem_name"] == "EFI_APPLICATION"
    assert pe["coff"]["machine_name"] == "AMD64"
    assert [section["name"] for section in pe["sections"]] == [".text", ".data"]
    assert pe["sections"][0]["characteristic_names"]["names"] == [
        "CNT_CODE", "MEM_EXECUTE", "MEM_READ"
    ]
    certificates = pe["certificate_table"]
    assert (certificates["offset"], certificates["size"], certificates["in_file"]) == (
        0x600, 72, True
    )
    assert certificates["verified"] is False
    assert certificates["entries"][0]["certificate_type_name"] == "PKCS_SIGNED_DATA"
    assert pe["data_directories"][4]["name"] == "SECURITY"
    assert pe["overlay"]["contains_certificate_table"] is True
    assert {"pe_partial_directory_coverage", "authenticode_not_verified"} <= set(
        staged.limitations
    )


def test_pe32_layout_is_parsed_separately_from_pe32_plus():
    status, fields, codes = triage_bytes(build_pe(plus=False, subsystem=3, machine=0x14C,
                                                  with_certificate=False))

    assert status == "observed"
    assert fields["pe"]["optional"]["format"] == "PE32"
    assert fields["pe"]["optional"]["image_base"] == 0x400000
    assert fields["pe"]["coff"]["machine_name"] == "I386"
    assert fields["pe"]["certificate_table"] is None
    assert codes == ["pe_partial_directory_coverage"]


def test_mz_without_pe_signature_and_scripts_are_unknown_not_failures():
    dos_only = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40) + b"\x00" * 64
    for data, expected_format in ((dos_only, "mz"), (b"#!/bin/sh\necho hi\n", None)):
        status, fields, codes = triage_bytes(data)
        assert status == "unknown"
        assert fields["format"] == expected_format
        assert fields["magic_hex"] == data[:16].hex()
        assert codes == ["binary_format_unsupported"]


def test_truncated_header_is_parse_failed_and_the_package_continues(tmp_path):
    source = tmp_path / "source"
    image = freebsd_kernel_module()
    binaries = [
        _binary(source, "a/truncated.ko", image[:40], logical_path="/boot/kernel/a.ko",
                declared_kind="kernel_module"),
        _binary(source, "b/intact.ko", image, logical_path="/boot/kernel/b.ko",
                declared_kind="kernel_module"),
    ]

    staged = import_binary_static(_package(binaries), source, tmp_path / "staging")

    failed, intact = _triage(staged, 0), _triage(staged, 1)
    assert failed["status"] == "parse_failed"
    assert failed["fields"]["parse_error"] == "truncated_elf_header"
    assert "elf" not in failed["fields"]
    assert intact["status"] == "observed"
    assert "binary_parse_failed:/boot/kernel/a.ko" in staged.limitations


def test_section_table_beyond_eof_is_a_partial_observation_with_issues():
    image = bytearray(freebsd_kernel_module())
    shoff = struct.unpack_from("<Q", image, 0x28)[0]
    truncated = bytes(image[: shoff + 64 * 4])

    status, fields, codes = triage_bytes(truncated)

    assert status == "observed"
    assert {"code": "section_table_truncated_by_eof", "where": "header"} in fields["parse_issues"]
    assert len(fields["elf"]["sections"]) == 4
    assert codes == ["binary_parse_issues"]


def test_unreadable_symbol_strings_are_an_issue_not_an_empty_table():
    image = bytearray(freebsd_kernel_module())
    shoff = struct.unpack_from("<Q", image, 0x28)[0]
    symtab_header = shoff + 6 * 64
    struct.pack_into("<I", image, symtab_header + 40, 99)  # sh_link -> no such section

    status, fields, _ = triage_bytes(bytes(image))

    assert status == "observed"
    (table,) = fields["elf"]["symbol_tables"]
    assert table["entry_count"] == 6 and table["undefined_count"] == 2
    assert all(symbol["name"] is None for symbol in table["symbols"])
    assert {"code": "symbol_string_table_unavailable", "where": "section:6"} in fields[
        "parse_issues"
    ]


def test_entropy_is_an_exact_fixed_point_string():
    assert shannon_entropy(byte_histogram(b"")) is None
    assert shannon_entropy(byte_histogram(b"\x00" * 4096)) == "0.000000"
    assert shannon_entropy(byte_histogram(bytes(range(256)) * 3)) == "8.000000"
    assert shannon_entropy(byte_histogram(b"ab" * 100)) == "1.000000"
    assert shannon_entropy(byte_histogram(b"aab")) == "0.918296"


def test_overlapping_sections_cannot_exhaust_measurement(tmp_path):
    sections = [
        {"name": f".s{index}", "type": SHT_PROGBITS, "data": b"\x41" * 4096}
        for index in range(8)
    ]
    image = bytearray(build_elf(sections)[0])
    shoff = struct.unpack_from("<Q", image, 0x28)[0]
    for index in range(1, 9):
        header = shoff + index * 64
        struct.pack_into("<QQ", image, header + 24, 0, len(image))  # every section = whole file

    status, fields, _ = triage_bytes(bytes(image))

    assert status == "observed"
    assert {"code": "measurement_budget_exhausted", "where": "file"} in fields["parse_issues"]
    measured = [s for s in fields["elf"]["sections"] if s["sha256"] is not None]
    assert 0 < len(measured) < 8


def test_one_triage_observation_per_binary_keyed_by_content(tmp_path):
    source = tmp_path / "source"
    image = freebsd_kernel_module()
    binaries = [
        _binary(source, "x/one.ko", image, logical_path="/boot/kernel/one.ko",
                declared_kind="kernel_module"),
        _binary(source, "y/two.ko", dynamic_executable(), logical_path="/bin/two",
                declared_kind="executable"),
    ]

    staged = import_binary_static(_package(binaries), source, tmp_path / "staging")

    triage = [o for o in _observations(staged.staging_root) if o["kind"] == "binary_triage"]
    assert [o["fields"]["content_sha256"] for o in triage] == [
        binaries[0]["sha256"], binaries[1]["sha256"]
    ]
    assert len({o["fields"]["content_sha256"] for o in triage}) == len(binaries)


def test_staging_is_byte_identical_across_runs(tmp_path):
    source = tmp_path / "source"
    binaries = [
        _binary(source, "k/mod.ko", freebsd_kernel_module(), logical_path="/boot/kernel/mod.ko",
                declared_kind="kernel_module"),
        _binary(source, "e/loader.efi", build_pe(), logical_path="/boot/loader.efi",
                declared_kind="boot_file"),
    ]
    package = _package(binaries)

    first = import_binary_static(package, source, tmp_path / "first")
    second = import_binary_static(package, source, tmp_path / "second")

    assert first.relative_paths == second.relative_paths
    for relative in first.relative_paths:
        assert (first.staging_root / relative).read_bytes() == (
            second.staging_root / relative
        ).read_bytes()


@pytest.mark.parametrize("seed", [0, 1, 2])
def test_mutated_binaries_never_escape_the_parser(seed):
    rng = random.Random(seed)
    corpus = [freebsd_kernel_module(), dynamic_executable(), build_pe(),
              build_pe(plus=False, with_certificate=False), build_pe_rich(),
              linux_kernel_module(), linux_executable()[0]]
    for _ in range(150):
        image = bytearray(rng.choice(corpus))
        for _ in range(rng.randint(1, 12)):
            position = rng.randrange(len(image))
            image[position] = rng.randrange(256)
        if rng.random() < 0.3:
            del image[rng.randrange(len(image)) :]
        status, fields, _ = triage_bytes(bytes(image))
        assert status in {"observed", "parse_failed", "unknown"}
        assert not str(fields["parse_error"] or "").startswith("internal_parser_error")


def test_package_validation_fails_closed(tmp_path):
    source = tmp_path / "source"
    image = freebsd_kernel_module()
    entry = _binary(source, "k/mod.ko", image, logical_path="/boot/kernel/mod.ko",
                    declared_kind="kernel_module")

    cases = [
        (dict(_package([entry]), extra=1), "unknown fields"),
        (_package([dict(entry, declared_kind="malware")]), "declared_kind"),
        (_package([entry, dict(entry)]), "duplicate source_path"),
        (_package([dict(entry, sha256="0" * 64)]), "SHA-256"),
        (_package([dict(entry, extra=1)]), "requires logical_path"),
        (_package([entry], {"engine": "clamav", "ruleset_source_path": "r.yar",
                            "ruleset_sha256": "0" * 64}), "engine must be 'yara'"),
        (_package([]), "1 to"),
    ]
    for index, (package, message) in enumerate(cases):
        with pytest.raises(OfflineEvidenceError, match=message):
            import_binary_static(package, source, tmp_path / f"staging-{index}")
    floating = _package([entry])
    floating["acquisition"] = dict(floating["acquisition"], vantage=1.5)
    with pytest.raises(OfflineEvidenceError, match="floating-point"):
        import_binary_static(floating, source, tmp_path / "staging-float")


def test_missing_signature_engine_yields_unknown_scans_never_clean(tmp_path, monkeypatch):
    import tools.binary_static.importer as importer

    monkeypatch.setattr(importer, "_signature_engine", lambda: None)
    source = tmp_path / "source"
    rules = _write(source, "rules/triage.yar", b"rule any { condition: true }\n")
    binaries = [
        _binary(source, "k/mod.ko", freebsd_kernel_module(), logical_path="/boot/kernel/mod.ko",
                declared_kind="kernel_module")
    ]
    signatures = {"engine": "yara", "ruleset_source_path": rules["source_path"],
                  "ruleset_sha256": rules["sha256"]}

    staged = import_binary_static(_package(binaries, signatures), source, tmp_path / "staging")

    by_kind = {o["kind"]: o for o in _observations(staged.staging_root)}
    assert by_kind["signature_ruleset"]["status"] == "unknown"
    scan = by_kind["signature_scan"]
    assert scan["status"] == "unknown"
    assert scan["fields"]["reason"] == "engine_unavailable"
    assert scan["fields"]["matched_rule_count"] is None
    assert "signature_engine_unavailable" in staged.limitations
    assert (staged.staging_root / "method/binary_static/rules/triage.yar").is_file()


def test_yara_matches_are_tool_reported_and_the_ruleset_is_frozen_as_method(tmp_path):
    pytest.importorskip("yara")
    source = tmp_path / "source"
    rules = _write(
        source,
        "rules/triage.yar",
        b'import "elf"\n'
        b'rule marker : demo { meta: author = "lab" strings: $m = "ZAYNOR_MARKER" '
        b"condition: $m }\n"
        b"rule relocatable { condition: elf.type == elf.ET_REL }\n",
    )
    binaries = [
        _binary(source, "k/mod.ko", freebsd_kernel_module(), logical_path="/boot/kernel/mod.ko",
                declared_kind="kernel_module"),
        _binary(source, "s/run.sh", b"#!/bin/sh\n", logical_path="/etc/rc.local",
                declared_kind="other"),
    ]
    signatures = {"engine": "yara", "ruleset_source_path": rules["source_path"],
                  "ruleset_sha256": rules["sha256"]}

    staged = import_binary_static(_package(binaries, signatures), source, tmp_path / "staging")

    observations = {o["observation_id"]: o for o in _observations(staged.staging_root)}
    ruleset = observations["binary_static:ruleset"]
    assert ruleset["status"] == "observed"
    assert ruleset["fields"]["rule_count"] == 2
    assert ruleset["fields"]["imported_modules"] == ["elf"]
    module_scan = observations["binary_static:000000:signatures"]
    assert module_scan["status"] == "observed"
    assert [m["rule"] for m in module_scan["fields"]["reported_matches"]] == [
        "marker", "relocatable"
    ]
    marker = module_scan["fields"]["reported_matches"][0]
    assert marker["tags"] == ["demo"] and marker["meta"] == {"author": "lab"}
    assert marker["strings"][0]["instances"][0]["length"] == len("ZAYNOR_MARKER")
    script_scan = observations["binary_static:000001:signatures"]
    assert script_scan["status"] == "observed"
    assert script_scan["fields"]["matched_rule_count"] == 0
    assert script_scan["fields"]["reported_matches"] == []
    manifest, _ = freeze_staged_evidence(staged, tmp_path / "cases")
    assert "method/binary_static/rules/triage.yar" in {e.relative_path for e in manifest.entries}


@pytest.mark.parametrize(
    "ruleset, reason",
    [
        (b'import "time"\nrule clock { condition: time.now() > 0 }\n',
         "nondeterministic_module_import"),
        (b'include "other.yar"\nrule a { condition: true }\n', "compile_error"),
        (b"\xff\xfe not utf-8", "ruleset_not_utf8"),
    ],
)
def test_nondeterministic_or_invalid_rulesets_are_rejected(tmp_path, ruleset, reason):
    pytest.importorskip("yara")
    source = tmp_path / "source"
    rules = _write(source, "rules/bad.yar", ruleset)
    binaries = [
        _binary(source, "k/mod.ko", freebsd_kernel_module(), logical_path="/boot/kernel/mod.ko",
                declared_kind="kernel_module")
    ]
    signatures = {"engine": "yara", "ruleset_source_path": rules["source_path"],
                  "ruleset_sha256": rules["sha256"]}

    staged = import_binary_static(_package(binaries, signatures), source, tmp_path / "staging")

    by_kind = {o["kind"]: o for o in _observations(staged.staging_root)}
    assert by_kind["signature_ruleset"]["status"] == "parse_failed"
    assert by_kind["signature_ruleset"]["fields"]["rejection_reason"] == reason
    assert by_kind["signature_scan"]["status"] == "unknown"
    assert f"signature_ruleset_rejected:{reason}" in staged.limitations


def test_combines_with_freebsd_evidence_for_the_same_acquisition(tmp_path):
    source = tmp_path / "source"
    image = freebsd_kernel_module()
    original = _write(source, "files/boot/kernel/if_test.ko", image)
    freebsd_package = _package([], module="freebsd_evidence")
    del freebsd_package["binaries"]
    freebsd_package["artifacts"] = [
        {"logical_path": "/boot/kernel/if_test.ko", "kind": "kernel_module",
         "collection_status": "collected", **original}
    ]
    binary_package = _package(
        [{"logical_path": "/boot/kernel/if_test.ko", "declared_kind": "kernel_module", **original}]
    )

    freebsd = import_freebsd_evidence(freebsd_package, source, tmp_path / "freebsd")
    binary = import_binary_static(binary_package, source, tmp_path / "binary")
    combined = combine_staged_evidence([freebsd, binary], tmp_path / "combined")
    manifest, _ = freeze_staged_evidence(combined, tmp_path / "cases")

    frozen = {entry.relative_path for entry in manifest.entries}
    assert "originals/freebsd_evidence/files/boot/kernel/if_test.ko" in frozen
    assert "originals/binary_static/files/boot/kernel/if_test.ko" in frozen
    lineages = {
        o["source"]["lineage_id"]
        for module in ("freebsd_evidence", "binary_static")
        for o in _observations(combined.staging_root, module)
    }
    assert lineages == {"lineage:disk-capture-001"}


def test_module_cli_stages_and_freezes_a_package_file(tmp_path):
    source = tmp_path / "source"
    binaries = [
        _binary(source, "k/mod.ko", freebsd_kernel_module(), logical_path="/boot/kernel/mod.ko",
                declared_kind="kernel_module")
    ]
    package = _package(binaries)
    package_path = tmp_path / "binary-package.json"
    package_path.write_text(json.dumps(package), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable, "-m", "tools.binary_static",
            "--package", str(package_path),
            "--source-root", str(source),
            "--staging-root", str(tmp_path / "cli-staging"),
            "--cases-root", str(tmp_path / "cli-cases"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["analysis_status"] == "analysis_unsupported"
    assert output["observation_count"] == 1
    assert (tmp_path / "cli-cases" / package["case_id"] / "manifest.json").is_file()



# --- Linux and Windows targets -------------------------------------------------


def test_linux_and_windows_targets_are_accepted(tmp_path):
    source = tmp_path / "source"
    linux = _package(
        [_binary(source, "lin/demo.ko", linux_kernel_module(),
                 logical_path="/lib/modules/6.8.0-45-generic/extra/demo.ko",
                 declared_kind="kernel_module")]
    )
    linux["target"] = TARGETS["Linux"]
    windows = _package(
        [_binary(source, "win/demo.dll", build_pe_rich(),
                 logical_path="C:\\Windows\\System32\\demo.dll", declared_kind="shared_object")]
    )
    windows["target"] = TARGETS["Windows"]

    linux_staged = import_binary_static(linux, source, tmp_path / "linux")
    windows_staged = import_binary_static(windows, source, tmp_path / "windows")

    assert _triage(linux_staged)["target"] == TARGETS["Linux"]
    assert _triage(windows_staged)["target"] == TARGETS["Windows"]
    assert "kernel_module_load_state_unknown" in linux_staged.limitations
    assert _triage(windows_staged)["fields"]["pe"]["exports"]["name"] == "demo.dll"


def test_unsupported_target_systems_fail_closed_and_freebsd_scope_is_kept(tmp_path):
    source = tmp_path / "source"
    entry = _binary(source, "k/mod.ko", freebsd_kernel_module(), logical_path="/k/mod.ko",
                    declared_kind="kernel_module")
    package = _package([entry])
    package["target"] = dict(TARGETS["Linux"], os="macOS")
    with pytest.raises(OfflineEvidenceError, match="'FreeBSD' or 'Linux' or 'Windows'"):
        import_binary_static(package, source, tmp_path / "binary")

    freebsd = _package([], module="freebsd_evidence")
    del freebsd["binaries"]
    freebsd["target"] = TARGETS["Linux"]
    freebsd["artifacts"] = [
        {"logical_path": "/k/mod.ko", "kind": "kernel_module", "collection_status": "collected",
         "source_path": entry["source_path"], "sha256": entry["sha256"]}
    ]
    with pytest.raises(OfflineEvidenceError, match="must be 'FreeBSD'$"):
        import_freebsd_evidence(freebsd, source, tmp_path / "freebsd")

    with pytest.raises(ValueError, match="allowed_os"):
        validate_package_context(_package([entry]), "binary_static",
                                 allowed_os=frozenset({"Plan9"}))


def test_linux_kernel_module_records_modinfo_and_build_id():
    status, fields, codes = triage_bytes(linux_kernel_module())

    assert status == "observed" and codes == []
    modinfo = {record["key"]: record["value"] for record in fields["elf"]["modinfo"]}
    assert modinfo["vermagic"] == "6.8.0-45-generic SMP preempt mod_unload modversions "
    assert modinfo["name"] == "demo_mod" and modinfo["depends"] == ""
    (note,) = fields["elf"]["notes"]
    assert note["build_id"] == bytes(range(20)).hex()
    assert fields["elf"]["entry_point"] is None  # ET_REL has no entry point


def test_linux_executable_records_version_needs_abi_tag_and_entry_section():
    image, layout = linux_executable()

    status, fields, codes = triage_bytes(image)

    assert status == "observed" and codes == []
    elf = fields["elf"]
    assert elf["version_needs"] == [
        {"file": "libc.so.6", "versions": [
            {"name": "GLIBC_2.34", "flags": 0, "index": 3},
            {"name": "GLIBC_2.2.5", "flags": 0, "index": 2},
        ]}
    ]
    abi = next(note for note in elf["notes"] if "gnu_abi_tag" in note)["gnu_abi_tag"]
    assert abi == {"os": 0, "os_name": "LINUX", "kernel_version": "3.2.0"}
    assert elf["interpreter"] == {"name": "/lib64/ld-linux-x86-64.so.2"}
    entry = elf["entry_point"]
    assert entry["section_name"] == ".text" and entry["segment_flag_names"] == ["R", "X"]
    loaded = [s for s in elf["sections"] if s["matches_load_segment"] is not None]
    assert loaded and all(s["matches_load_segment"] for s in loaded)


def test_section_table_that_disagrees_with_the_loader_is_visible():
    image, layout = linux_executable()
    text = layout[".text"]
    shoff = struct.unpack_from("<Q", image, 0x28)[0]
    patched = bytearray(image)
    struct.pack_into("<Q", patched, shoff + text["index"] * 64 + 24, text["offset"] + 3)

    status, fields, codes = triage_bytes(bytes(patched))

    assert status == "observed"
    assert fields["elf"]["sections"][text["index"]]["matches_load_segment"] is False
    where = f"section:{text['index']}"
    assert {"code": "section_offset_misaligned", "where": where} in fields["parse_issues"]
    assert {"code": "section_not_mapped_as_declared", "where": where} in fields["parse_issues"]
    assert codes == ["binary_parse_issues"]


def test_windows_dll_triage_reads_what_windows_triage_needs():
    status, fields, codes = triage_bytes(build_pe_rich())

    assert status == "observed" and fields["parse_issues"] == []
    assert codes == ["pe_partial_directory_coverage", "authenticode_not_verified"]
    pe = fields["pe"]
    rich = pe["rich_header"]
    assert rich["checksum_valid"] and rich["padding_valid"]
    assert [(e["product_id"], e["build"], e["count"]) for e in rich["entries"]] == list(
        RICH_ENTRIES
    )
    assert pe["optional"]["computed_checksum"] == pe["optional"]["checksum"] != 0
    assert pe["entry_point"]["section_name"] == ".text"
    kernel32, ws2 = pe["imports"]
    assert kernel32["name"] == "KERNEL32.dll"
    assert [(f["name"], f["hint"]) for f in kernel32["functions"]] == [
        ("CreateFileW", 0xC4), ("Sleep", 0x5A)
    ]
    assert ws2["functions"] == [{"ordinal": 23}]  # the literal import; no name lookup
    (delay,) = pe["delay_imports"]
    assert delay["name"] == "USER32.dll" and delay["functions"][0]["name"] == "MessageBoxW"
    exports = pe["exports"]
    assert exports["name"] == "demo.dll"
    assert [(e["ordinal"], e["names"], e["forwarder"]) for e in exports["functions"]] == [
        (1, ["DemoExport"], None), (2, ["DemoForward"], "NTDLL.RtlAllocateHeap"), (3, [], None)
    ]
    codeview, repro = pe["debug"]
    assert codeview["codeview"]["pdb_path"] == {"name": PDB_PATH}
    assert codeview["codeview"]["guid"] == "03020100-0504-0706-0809-0A0B0C0D0E0F"
    assert repro["type_name"] == "REPRO"
    assert [(c["rva"], c["section_name"]) for c in pe["tls"]["callbacks"]] == [
        (0x1030, ".text"), (0x1040, ".text")
    ]
    resources = pe["resources"]
    assert [(t["type_label"], t["count"]) for t in resources["types"]] == [
        ("RCDATA", 1), ("VERSION", 1)
    ]
    rcdata = next(leaf for leaf in resources["leaves"] if leaf["type_label"] == "RCDATA")
    assert rcdata["sha256"] == _sha256(bytes(range(64)))
    version = resources["version_info"]
    assert version["fixed"]["file_version"] == "1.2.3.4"
    assert {item["key"]: item["value"] for item in version["strings"]} == dict(VERSION_STRINGS)
    assert version["translations"] == [{"language": 0x0409, "codepage": 0x04B0}]
    overlay = pe["overlay"]
    assert overlay["offset"] == 0x1200 and overlay["contains_certificate_table"] is True
    assert pe["certificate_table"]["entries"][0]["certificate_type_name"] == "PKCS_SIGNED_DATA"
    listed = {(item["encoding"], item["value"]) for item in fields["strings"]["listed"]}
    assert ("ascii", "https://updates.example.invalid/check") in listed
    assert ("utf-16le", "Software\\Demo\\Settings") in listed


def test_resource_directory_cycles_are_cut_not_followed():
    image = bytearray(build_pe_rich())
    resource_raw = 0xE00
    # Point the RCDATA name directory back at the root directory.
    struct.pack_into("<I", image, resource_raw + 0x20 + 16 + 4, 0x80000000)

    status, fields, _ = triage_bytes(bytes(image))

    assert status == "observed"
    assert {"code": "resource_directory_cycle", "where": "resource"} in fields["parse_issues"]


def test_strings_are_listed_by_position_in_both_encodings():
    data = (
        b"\x00\x01short\x00/usr/bin/env python3\x00\x00"
        + "Global\\Demo".encode("utf-16-le") + b"\x00\x00" + b"A" * 300
    )

    strings = extract_strings(data)

    assert strings["min_chars"] == 6
    assert [(item["encoding"], item["value"]) for item in strings["listed"][:2]] == [
        ("ascii", "/usr/bin/env python3"), ("utf-16le", "Global\\Demo")
    ]
    long_run = strings["listed"][2]
    assert long_run["length"] == 300 and long_run["value_truncated"] is True
    assert len(long_run["value"]) == 200
    assert strings["total"] == 3 and strings["listing_truncated"] is False
