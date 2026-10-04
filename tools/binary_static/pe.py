"""Bounded, read-only PE/COFF header parser for static triage.

Scope is the image headers only (PBA ch. 3): DOS stub pointer, COFF file
header, optional header, data-directory table and section table, with a
hash and entropy per in-file section. Import/export/resource/debug
directories are located but not walked, and an Authenticode certificate
table is reported as present, never verified. On FreeBSD these images are
mostly the UEFI boot chain (``loader.efi``, ``boot1.efi``), which is why a
FreeBSD-scoped module reads PE at all.

Only an unusable header raises :class:`PeFormatError`; an MZ file without a
PE signature is reported by :func:`parse_pe` returning ``None`` so that the
caller records an unsupported format instead of a parse failure.
"""

from __future__ import annotations

import struct
from typing import Any

from tools.binary_static.elf import decode_name
from tools.binary_static.measure import MeasurementBudget, measure_range

MAX_PE_SECTIONS = 96
MAX_DATA_DIRECTORIES = 16

LIMITS = {"max_sections": MAX_PE_SECTIONS, "max_data_directories": MAX_DATA_DIRECTORIES}

_MACHINES = {
    0x0: "UNKNOWN", 0x14C: "I386", 0x1C0: "ARM", 0x1C4: "ARMNT", 0x200: "IA64",
    0x5032: "RISCV32", 0x5064: "RISCV64", 0x8664: "AMD64", 0xAA64: "ARM64", 0xEBC: "EBC",
}
_COFF_CHARACTERISTICS = (
    (0x0001, "RELOCS_STRIPPED"), (0x0002, "EXECUTABLE_IMAGE"), (0x0004, "LINE_NUMS_STRIPPED"),
    (0x0008, "LOCAL_SYMS_STRIPPED"), (0x0010, "AGGRESSIVE_WS_TRIM"),
    (0x0020, "LARGE_ADDRESS_AWARE"), (0x0080, "BYTES_REVERSED_LO"), (0x0100, "32BIT_MACHINE"),
    (0x0200, "DEBUG_STRIPPED"), (0x0400, "REMOVABLE_RUN_FROM_SWAP"),
    (0x0800, "NET_RUN_FROM_SWAP"), (0x1000, "SYSTEM"), (0x2000, "DLL"),
    (0x4000, "UP_SYSTEM_ONLY"), (0x8000, "BYTES_REVERSED_HI"),
)
_SUBSYSTEMS = {
    1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION", 11: "EFI_BOOT_SERVICE_DRIVER", 12: "EFI_RUNTIME_DRIVER",
    13: "EFI_ROM", 14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION",
}
_DLL_CHARACTERISTICS = (
    (0x0020, "HIGH_ENTROPY_VA"), (0x0040, "DYNAMIC_BASE"), (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT"), (0x0200, "NO_ISOLATION"), (0x0400, "NO_SEH"), (0x0800, "NO_BIND"),
    (0x1000, "APPCONTAINER"), (0x2000, "WDM_DRIVER"), (0x4000, "GUARD_CF"),
    (0x8000, "TERMINAL_SERVER_AWARE"),
)
_SECTION_CHARACTERISTICS = (
    (0x00000020, "CNT_CODE"), (0x00000040, "CNT_INITIALIZED_DATA"),
    (0x00000080, "CNT_UNINITIALIZED_DATA"), (0x00000200, "LNK_INFO"),
    (0x00000800, "LNK_REMOVE"), (0x00001000, "LNK_COMDAT"), (0x00008000, "GPREL"),
    (0x01000000, "LNK_NRELOC_OVFL"), (0x02000000, "MEM_DISCARDABLE"),
    (0x04000000, "MEM_NOT_CACHED"), (0x08000000, "MEM_NOT_PAGED"), (0x10000000, "MEM_SHARED"),
    (0x20000000, "MEM_EXECUTE"), (0x40000000, "MEM_READ"), (0x80000000, "MEM_WRITE"),
)
_DIRECTORY_NAMES = (
    "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG",
    "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT",
    "DELAY_IMPORT", "CLR_RUNTIME", "RESERVED",
)
_SECURITY_DIRECTORY = 4
_PE32, _PE32_PLUS = 0x10B, 0x20B
# Optional-header layouts up to (and including) NumberOfRvaAndSizes.
_OPTIONAL_PE32 = struct.Struct("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII")
_OPTIONAL_PE32_PLUS = struct.Struct("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII")
_COFF = struct.Struct("<HHIIIHH")
_SECTION = struct.Struct("<8sIIIIIIHHI")
_DIRECTORY = struct.Struct("<II")


class PeFormatError(ValueError):
    """The PE headers cannot be parsed; nothing below them is trustworthy."""


def _flags(value: int, table: tuple[tuple[int, str], ...]) -> dict[str, Any]:
    names = [name for bit, name in table if value & bit]
    known = 0
    for bit, _ in table:
        known |= bit
    result: dict[str, Any] = {"names": names}
    if value & ~known:
        result["unknown_bits"] = value & ~known
    return result


def parse_pe(data: bytes) -> tuple[dict[str, Any], list[dict[str, str]]] | None:
    """Parse PE image headers; ``None`` when MZ has no PE signature."""
    size = len(data)
    issues: list[dict[str, str]] = []
    if size < 0x40 or data[:2] != b"MZ":
        raise PeFormatError("truncated_dos_header")
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if e_lfanew + 4 > size or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    coff_offset = e_lfanew + 4
    if coff_offset + _COFF.size > size:
        raise PeFormatError("truncated_coff_header")
    (
        machine, number_of_sections, time_date_stamp, pointer_to_symbol_table,
        number_of_symbols, size_of_optional_header, characteristics,
    ) = _COFF.unpack_from(data, coff_offset)
    optional_offset = coff_offset + _COFF.size
    optional_end = optional_offset + size_of_optional_header
    if optional_end > size:
        raise PeFormatError("truncated_optional_header")
    if size_of_optional_header < 2:
        raise PeFormatError("missing_optional_header")
    (magic,) = struct.unpack_from("<H", data, optional_offset)
    if magic == _PE32:
        layout, image_format = _OPTIONAL_PE32, "PE32"
    elif magic == _PE32_PLUS:
        layout, image_format = _OPTIONAL_PE32_PLUS, "PE32+"
    else:
        raise PeFormatError("unsupported_optional_header_magic")
    if size_of_optional_header < layout.size:
        raise PeFormatError("optional_header_shorter_than_layout")
    values = layout.unpack_from(data, optional_offset)
    if magic == _PE32:
        (
            _, major_linker, minor_linker, size_of_code, _init, _uninit, entry_point,
            base_of_code, _base_of_data, image_base, section_alignment, file_alignment,
            major_os, minor_os, _major_image, _minor_image, major_subsystem, minor_subsystem,
            _win32_version, size_of_image, size_of_headers, checksum, subsystem,
            dll_characteristics, _sr, _sc, _hr, _hc, _loader_flags, number_of_rva_and_sizes,
        ) = values
    else:
        (
            _, major_linker, minor_linker, size_of_code, _init, _uninit, entry_point,
            base_of_code, image_base, section_alignment, file_alignment,
            major_os, minor_os, _major_image, _minor_image, major_subsystem, minor_subsystem,
            _win32_version, size_of_image, size_of_headers, checksum, subsystem,
            dll_characteristics, _sr, _sc, _hr, _hc, _loader_flags, number_of_rva_and_sizes,
        ) = values

    directories: list[dict[str, Any]] = []
    directory_offset = optional_offset + layout.size
    room = (optional_end - directory_offset) // _DIRECTORY.size
    declared = number_of_rva_and_sizes
    count = min(declared, room, MAX_DATA_DIRECTORIES)
    if declared > MAX_DATA_DIRECTORIES:
        issues.append({"code": "data_directory_count_exceeds_maximum", "where": "optional_header"})
    if min(declared, MAX_DATA_DIRECTORIES) > room:
        issues.append({"code": "data_directories_truncated_by_header", "where": "optional_header"})
    certificate_table = None
    for index in range(count):
        rva, dir_size = _DIRECTORY.unpack_from(data, directory_offset + index * _DIRECTORY.size)
        directories.append(
            {"index": index, "name": _DIRECTORY_NAMES[index], "rva": rva, "size": dir_size}
        )
        if index == _SECURITY_DIRECTORY and dir_size:
            # The security directory holds a FILE offset, not an RVA.
            in_file = rva + dir_size <= size
            certificate_table = {"offset": rva, "size": dir_size, "in_file": in_file}
            if not in_file:
                issues.append({"code": "certificate_table_out_of_bounds", "where": "directory:4"})

    sections: list[dict[str, Any]] = []
    table_offset = optional_end
    listed = min(number_of_sections, MAX_PE_SECTIONS)
    if number_of_sections > MAX_PE_SECTIONS:
        issues.append({"code": "section_listing_capped", "where": "coff_header"})
    budget = MeasurementBudget(4 * max(size, 1))
    view = memoryview(data)
    for index in range(listed):
        entry_offset = table_offset + index * _SECTION.size
        if entry_offset + _SECTION.size > size:
            issues.append({"code": "section_table_truncated_by_eof", "where": "coff_header"})
            break
        (
            raw_name, virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data,
            _reloc_ptr, _line_ptr, _reloc_count, _line_count, section_characteristics,
        ) = _SECTION.unpack_from(data, entry_offset)
        record: dict[str, Any] = {
            "index": index,
            **decode_name(raw_name.rstrip(b"\x00")),
            "virtual_size": virtual_size,
            "virtual_address": virtual_address,
            "size_of_raw_data": size_of_raw_data,
            "pointer_to_raw_data": pointer_to_raw_data,
            "characteristics": section_characteristics,
            "characteristic_names": _flags(section_characteristics, _SECTION_CHARACTERISTICS),
            "in_file": False,
            "sha256": None,
            "entropy_bits_per_byte": None,
        }
        if size_of_raw_data:
            in_file = pointer_to_raw_data + size_of_raw_data <= size
            record["in_file"] = in_file
            if not in_file:
                issues.append({"code": "section_data_out_of_bounds", "where": f"section:{index}"})
            elif budget.take(size_of_raw_data):
                record.update(measure_range(view, pointer_to_raw_data, size_of_raw_data))
        sections.append(record)
    if budget.exhausted:
        issues.append({"code": "measurement_budget_exhausted", "where": "file"})

    fields = {
        "dos": {"e_lfanew": e_lfanew},
        "coff": {
            "machine": machine,
            "machine_name": _MACHINES.get(machine),
            "number_of_sections": number_of_sections,
            "time_date_stamp": time_date_stamp,
            "pointer_to_symbol_table": pointer_to_symbol_table,
            "number_of_symbols": number_of_symbols,
            "size_of_optional_header": size_of_optional_header,
            "characteristics": characteristics,
            "characteristic_names": _flags(characteristics, _COFF_CHARACTERISTICS),
        },
        "optional": {
            "magic": magic,
            "format": image_format,
            "linker_version": [major_linker, minor_linker],
            "size_of_code": size_of_code,
            "address_of_entry_point": entry_point,
            "base_of_code": base_of_code,
            "image_base": image_base,
            "section_alignment": section_alignment,
            "file_alignment": file_alignment,
            "os_version": [major_os, minor_os],
            "subsystem_version": [major_subsystem, minor_subsystem],
            "size_of_image": size_of_image,
            "size_of_headers": size_of_headers,
            "checksum": checksum,
            "subsystem": subsystem,
            "subsystem_name": _SUBSYSTEMS.get(subsystem),
            "dll_characteristics": dll_characteristics,
            "dll_characteristic_names": _flags(dll_characteristics, _DLL_CHARACTERISTICS),
            "number_of_rva_and_sizes": number_of_rva_and_sizes,
        },
        "data_directories": directories,
        "certificate_table": certificate_table,
        "sections": sections,
        "limits": dict(LIMITS),
    }
    return fields, issues
