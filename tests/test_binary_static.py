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
from tools.binary_static.measure import byte_histogram, shannon_entropy
from tools.freebsd_evidence import import_freebsd_evidence
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
    certificate = b"\x30\x82" + b"\x00" * 62
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
    assert pe["certificate_table"] == {"offset": 0x600, "size": 64, "in_file": True}
    assert pe["data_directories"][4]["name"] == "SECURITY"
    assert {"pe_data_directories_not_walked", "authenticode_not_verified"} <= set(
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
    assert codes == ["pe_data_directories_not_walked"]


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
              build_pe(plus=False, with_certificate=False)]
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
