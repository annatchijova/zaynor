"""Bounded, read-only PE/COFF parser for static triage.

Covers what Windows triage reads without executing anything (PBA ch. 3 for
the format): DOS and Rich headers, COFF and optional headers, data
directories, sections, entry-point placement, imports and delay imports,
exports (with forwarders), debug directory (CodeView PDB path, reproducible
build marker), TLS callback table, resources (type summary, per-leaf hashes,
version information), overlay, the header checksum recomputed, and the
Authenticode certificate table described but never verified.

Every RVA is mapped through the section table literally and every read is a
bounds-checked view of the size-bounded input. Directory walks are capped and
cycle-protected; a cap that is reached or a structure that cannot be read is
a parse issue, never an empty result.

Only unusable headers raise :class:`PeFormatError`; an MZ file without a PE
signature makes :func:`parse_pe` return ``None`` so that the caller records
an unsupported format instead of a parse failure.
"""

from __future__ import annotations

import struct
import sys
from array import array
from typing import Any

from tools.binary_static.elf import decode_name
from tools.binary_static.measure import MeasurementBudget, measure_range, sha256_hex

MAX_PE_SECTIONS = 96
MAX_DATA_DIRECTORIES = 16
MAX_IMPORT_DESCRIPTORS = 1024
MAX_DELAY_DESCRIPTORS = 256
MAX_THUNKS_PER_MODULE = 8192
MAX_IMPORTS_LISTED = 16384
MAX_EXPORTS_LISTED = 16384
MAX_DEBUG_ENTRIES = 32
MAX_TLS_CALLBACKS = 64
MAX_RESOURCE_LEAVES = 4096
MAX_RESOURCE_LEAVES_LISTED = 256
MAX_RESOURCE_DEPTH = 3
MAX_RICH_ENTRIES = 256
MAX_CERTIFICATES = 8
MAX_NAME_BYTES = 512
MAX_VERSION_STRINGS = 128
MAX_VERSION_TEXT = 512
MAX_VERSION_DEPTH = 6
MAX_ISSUES = 256

LIMITS = {
    "max_sections": MAX_PE_SECTIONS,
    "max_data_directories": MAX_DATA_DIRECTORIES,
    "max_import_descriptors": MAX_IMPORT_DESCRIPTORS,
    "max_imports_listed": MAX_IMPORTS_LISTED,
    "max_exports_listed": MAX_EXPORTS_LISTED,
    "max_debug_entries": MAX_DEBUG_ENTRIES,
    "max_tls_callbacks": MAX_TLS_CALLBACKS,
    "max_resource_leaves": MAX_RESOURCE_LEAVES,
    "max_resource_leaves_listed": MAX_RESOURCE_LEAVES_LISTED,
    "max_version_strings": MAX_VERSION_STRINGS,
}

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
_DEBUG_TYPES = {
    0: "UNKNOWN", 1: "COFF", 2: "CODEVIEW", 3: "FPO", 4: "MISC", 5: "EXCEPTION", 6: "FIXUP",
    7: "OMAP_TO_SRC", 8: "OMAP_FROM_SRC", 9: "BORLAND", 10: "RESERVED10", 11: "CLSID",
    12: "VC_FEATURE", 13: "POGO", 14: "ILTCG", 15: "MPX", 16: "REPRO",
    20: "EX_DLLCHARACTERISTICS",
}
_RESOURCE_TYPES = {
    1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING", 7: "FONTDIR",
    8: "FONT", 9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR",
    14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE", 19: "PLUGPLAY", 20: "VXD",
    21: "ANICURSOR", 22: "ANIICON", 23: "HTML", 24: "MANIFEST",
}
_CERTIFICATE_TYPES = {1: "X509", 2: "PKCS_SIGNED_DATA", 3: "RESERVED_1", 4: "TS_STACK_SIGNED"}

_EXPORT, _IMPORT, _RESOURCE, _SECURITY, _DEBUG, _TLS, _DELAY_IMPORT = 0, 1, 2, 4, 6, 9, 13
_RT_VERSION = 16
_DEBUG_CODEVIEW = 2
_FIXED_FILE_INFO_SIGNATURE = 0xFEEF04BD
_DANS = 0x536E6144
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


def _rol32(value: int, bits: int) -> int:
    bits %= 32
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF if bits else value


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _guid(raw: bytes) -> str:
    data1, data2, data3 = struct.unpack_from("<IHH", raw, 0)
    tail = raw[8:16].hex().upper()
    return f"{data1:08X}-{data2:04X}-{data3:04X}-{tail[:4]}-{tail[4:]}"


def pe_checksum(data: bytes, checksum_offset: int) -> int:
    """The optional-header checksum recomputed with the field treated as zero."""
    zeroed = data[:checksum_offset] + b"\x00\x00\x00\x00" + data[checksum_offset + 4 :]
    if len(zeroed) % 2:
        zeroed += b"\x00"
    words = array("H")
    words.frombytes(zeroed)
    if sys.byteorder == "big":
        words.byteswap()
    total = sum(words)
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (total + len(data)) & 0xFFFFFFFF


class _Pe:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.view = memoryview(data)
        self.size = len(data)
        self.issues: list[dict[str, str]] = []
        self._issue_overflow = False
        self.is_plus = False
        self.image_base = 0
        self.size_of_headers = 0
        self.raw_sections: list[tuple[int, int, int, int, dict[str, Any]]] = []
        self.budget = MeasurementBudget(4 * max(self.size, 1))

    # -- primitives ---------------------------------------------------------

    def issue(self, code: str, where: str = "") -> None:
        if len(self.issues) >= MAX_ISSUES:
            if not self._issue_overflow:
                self._issue_overflow = True
                self.issues.append({"code": "issue_limit_reached", "where": ""})
            return
        self.issues.append({"code": code, "where": where})

    def u(self, fmt: str, offset: int) -> tuple[Any, ...] | None:
        size = struct.calcsize("<" + fmt)
        if offset < 0 or offset + size > self.size:
            return None
        return struct.unpack_from("<" + fmt, self.data, offset)

    def map_rva(self, rva: int) -> tuple[int, int] | None:
        """File offset of an RVA and the end of the file range backing it."""
        if rva < 0:
            return None
        header_end = min(self.size_of_headers, self.size)
        if self.raw_sections:
            header_end = min(header_end, min(entry[0] for entry in self.raw_sections))
        if rva < header_end:
            return rva, header_end
        for virtual_address, virtual_size, pointer, raw_size, _ in self.raw_sections:
            span = max(virtual_size, raw_size)
            if virtual_address <= rva < virtual_address + span:
                delta = rva - virtual_address
                end = min(pointer + raw_size, self.size)
                if delta < raw_size and pointer + delta < end:
                    return pointer + delta, end
                return None
        return None

    def section_of(self, rva: int) -> dict[str, Any] | None:
        for virtual_address, virtual_size, _, raw_size, record in self.raw_sections:
            if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
                return record
        return None

    def u_rva(self, fmt: str, rva: int) -> tuple[Any, ...] | None:
        mapped = self.map_rva(rva)
        if mapped is None:
            return None
        offset, end = mapped
        if offset + struct.calcsize("<" + fmt) > end:
            return None
        return struct.unpack_from("<" + fmt, self.data, offset)

    def ascii_at_rva(self, rva: int, where: str) -> dict[str, Any]:
        mapped = self.map_rva(rva)
        if mapped is None:
            self.issue("string_rva_unmapped", where)
            return {"name": None}
        offset, end = mapped
        terminator = self.data.find(b"\x00", offset, min(end, offset + MAX_NAME_BYTES + 1))
        truncated = False
        if terminator == -1:
            if end - offset > MAX_NAME_BYTES:
                terminator, truncated = offset + MAX_NAME_BYTES, True
                self.issue("name_truncated", where)
            else:
                self.issue("unterminated_name", where)
                return {"name": None}
        return decode_name(self.data[offset:terminator], truncated)

    def directory(self, directories: list[dict[str, Any]], index: int) -> tuple[int, int] | None:
        if index >= len(directories):
            return None
        rva, size = directories[index]["rva"], directories[index]["size"]
        if rva == 0 or size == 0:
            return None
        return rva, size

    # -- headers ------------------------------------------------------------

    def parse(self) -> dict[str, Any] | None:
        data, size = self.data, self.size
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
        self.is_plus = magic == _PE32_PLUS
        if self.is_plus:
            (
                _, major_linker, minor_linker, size_of_code, _init, _uninit, entry_point,
                base_of_code, image_base, section_alignment, file_alignment,
                major_os, minor_os, _major_image, _minor_image, major_subsystem,
                minor_subsystem, _win32_version, size_of_image, size_of_headers, checksum,
                subsystem, dll_characteristics, _sr, _sc, _hr, _hc, _loader_flags,
                number_of_rva_and_sizes,
            ) = values
        else:
            (
                _, major_linker, minor_linker, size_of_code, _init, _uninit, entry_point,
                base_of_code, _base_of_data, image_base, section_alignment, file_alignment,
                major_os, minor_os, _major_image, _minor_image, major_subsystem,
                minor_subsystem, _win32_version, size_of_image, size_of_headers, checksum,
                subsystem, dll_characteristics, _sr, _sc, _hr, _hc, _loader_flags,
                number_of_rva_and_sizes,
            ) = values
        self.image_base = image_base
        self.size_of_headers = size_of_headers

        directories = self._directories(optional_offset + layout.size, optional_end,
                                        number_of_rva_and_sizes)
        sections = self._sections(optional_end, number_of_sections)
        checksum_offset = optional_offset + 64
        certificates = self._certificates(directories)

        fields: dict[str, Any] = {
            "dos": {"e_lfanew": e_lfanew},
            "rich_header": self._rich_header(e_lfanew),
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
                "computed_checksum": pe_checksum(data, checksum_offset),
                "subsystem": subsystem,
                "subsystem_name": _SUBSYSTEMS.get(subsystem),
                "dll_characteristics": dll_characteristics,
                "dll_characteristic_names": _flags(dll_characteristics, _DLL_CHARACTERISTICS),
                "number_of_rva_and_sizes": number_of_rva_and_sizes,
            },
            "data_directories": directories,
            "sections": sections,
            "entry_point": self._entry_point(entry_point),
            "imports": self._imports(directories),
            "delay_imports": self._delay_imports(directories),
            "exports": self._exports(directories),
            "debug": self._debug(directories),
            "tls": self._tls(directories),
            "resources": self._resources(directories),
            "certificate_table": certificates,
            "overlay": None,
            "limits": dict(LIMITS),
        }
        fields["overlay"] = self._overlay(certificates)
        if self.budget.exhausted:
            self.issue("measurement_budget_exhausted", "file")
        return fields

    def _directories(self, offset: int, end: int, declared: int) -> list[dict[str, Any]]:
        room = (end - offset) // _DIRECTORY.size
        count = min(declared, room, MAX_DATA_DIRECTORIES)
        if declared > MAX_DATA_DIRECTORIES:
            self.issue("data_directory_count_exceeds_maximum", "optional_header")
        if min(declared, MAX_DATA_DIRECTORIES) > room:
            self.issue("data_directories_truncated_by_header", "optional_header")
        directories = []
        for index in range(count):
            rva, dir_size = _DIRECTORY.unpack_from(self.data, offset + index * _DIRECTORY.size)
            directories.append(
                {"index": index, "name": _DIRECTORY_NAMES[index], "rva": rva, "size": dir_size}
            )
        return directories

    def _sections(self, table_offset: int, declared: int) -> list[dict[str, Any]]:
        listed = min(declared, MAX_PE_SECTIONS)
        if declared > MAX_PE_SECTIONS:
            self.issue("section_listing_capped", "coff_header")
        sections: list[dict[str, Any]] = []
        for index in range(listed):
            entry_offset = table_offset + index * _SECTION.size
            if entry_offset + _SECTION.size > self.size:
                self.issue("section_table_truncated_by_eof", "coff_header")
                break
            (
                raw_name, virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data,
                _reloc_ptr, _line_ptr, _reloc_count, _line_count, characteristics,
            ) = _SECTION.unpack_from(self.data, entry_offset)
            record: dict[str, Any] = {
                "index": index,
                **decode_name(raw_name.rstrip(b"\x00")),
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "size_of_raw_data": size_of_raw_data,
                "pointer_to_raw_data": pointer_to_raw_data,
                "characteristics": characteristics,
                "characteristic_names": _flags(characteristics, _SECTION_CHARACTERISTICS),
                "in_file": False,
                "sha256": None,
                "entropy_bits_per_byte": None,
            }
            if size_of_raw_data:
                in_file = pointer_to_raw_data + size_of_raw_data <= self.size
                record["in_file"] = in_file
                if not in_file:
                    self.issue("section_data_out_of_bounds", f"section:{index}")
                elif self.budget.take(size_of_raw_data):
                    record.update(
                        measure_range(self.view, pointer_to_raw_data, size_of_raw_data)
                    )
            self.raw_sections.append(
                (virtual_address, virtual_size, pointer_to_raw_data,
                 size_of_raw_data if record["in_file"] else 0, record)
            )
            sections.append(record)
        return sections

    def _entry_point(self, rva: int) -> dict[str, Any]:
        section = self.section_of(rva) if rva else None
        return {
            "rva": rva,
            "section_index": section["index"] if section else None,
            "section_name": section.get("name") if section else None,
            "in_file": self.map_rva(rva) is not None if rva else False,
        }

    # -- Rich header --------------------------------------------------------

    def _rich_header(self, e_lfanew: int) -> dict[str, Any] | None:
        window_end = min(e_lfanew, self.size)
        rich = self.data.find(b"Rich", 0x40, window_end)
        if rich == -1 or rich % 4 or rich + 8 > window_end:
            return None
        (key,) = struct.unpack_from("<I", self.data, rich + 4)
        position = rich - 4
        dans = None
        lowest = max(0x40, rich - 16 - 8 * MAX_RICH_ENTRIES)
        while position >= lowest:
            (value,) = struct.unpack_from("<I", self.data, position)
            if value ^ key == _DANS:
                dans = position
                break
            position -= 4
        if dans is None:
            self.issue("rich_header_start_not_found", "dos_stub")
            return {"offset": None, "key": key, "entries": [], "checksum_valid": False}
        padding_valid = all(
            struct.unpack_from("<I", self.data, dans + 4 * step)[0] ^ key == 0
            for step in (1, 2, 3)
        )
        entries = []
        checksum = dans
        for index in range(dans):
            if 0x3C <= index < 0x40:
                continue
            checksum = (checksum + _rol32(self.data[index], index)) & 0xFFFFFFFF
        for offset in range(dans + 16, rich - 7, 8):
            comp_id, count = struct.unpack_from("<II", self.data, offset)
            comp_id ^= key
            count ^= key
            entries.append({"product_id": comp_id >> 16, "build": comp_id & 0xFFFF,
                            "count": count})
            checksum = (checksum + _rol32(comp_id, count)) & 0xFFFFFFFF
        return {
            "offset": dans,
            "key": key,
            "entries": entries,
            "padding_valid": padding_valid,
            "checksum_valid": checksum == key,
        }

    # -- imports and exports ------------------------------------------------

    def _thunks(self, rva: int, where: str, budget: list[int]) -> tuple[list[dict[str, Any]], int]:
        width = 8 if self.is_plus else 4
        ordinal_flag = 1 << (63 if self.is_plus else 31)
        functions: list[dict[str, Any]] = []
        count = 0
        for index in range(MAX_THUNKS_PER_MODULE + 1):
            if index == MAX_THUNKS_PER_MODULE:
                self.issue("import_thunk_listing_capped", where)
                break
            raw = self.u_rva("Q" if self.is_plus else "I", rva + index * width)
            if raw is None:
                self.issue("import_thunk_table_unmapped", where)
                break
            (value,) = raw
            if value == 0:
                break
            count += 1
            if budget[0] <= 0:
                continue
            budget[0] -= 1
            if value & ordinal_flag:
                functions.append({"ordinal": value & 0xFFFF})
                continue
            hint_rva = value & 0x7FFFFFFF
            hint = self.u_rva("H", hint_rva)
            entry: dict[str, Any] = {"hint": hint[0] if hint else None}
            entry.update(self.ascii_at_rva(hint_rva + 2, where))
            functions.append(entry)
        return functions, count

    def _imports(self, directories: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
        located = self.directory(directories, _IMPORT)
        if located is None:
            return None
        rva, _ = located
        budget = [MAX_IMPORTS_LISTED]
        modules: list[dict[str, Any]] = []
        for index in range(MAX_IMPORT_DESCRIPTORS + 1):
            where = f"import:{index}"
            if index == MAX_IMPORT_DESCRIPTORS:
                self.issue("import_descriptor_listing_capped", "import")
                break
            raw = self.u_rva("IIIII", rva + 20 * index)
            if raw is None:
                self.issue("import_descriptor_unmapped", where)
                break
            original_first_thunk, time_date_stamp, forwarder_chain, name_rva, first_thunk = raw
            if not any(raw):
                break
            functions, count = self._thunks(original_first_thunk or first_thunk, where, budget)
            modules.append(
                {
                    **self.ascii_at_rva(name_rva, where),
                    "time_date_stamp": time_date_stamp,
                    "forwarder_chain": forwarder_chain,
                    "uses_original_first_thunk": original_first_thunk != 0,
                    "function_count": count,
                    "functions": functions,
                }
            )
        if budget[0] <= 0:
            self.issue("import_listing_capped", "import")
        return modules

    def _delay_imports(self, directories: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
        located = self.directory(directories, _DELAY_IMPORT)
        if located is None:
            return None
        rva, _ = located
        budget = [MAX_IMPORTS_LISTED]
        modules: list[dict[str, Any]] = []
        for index in range(MAX_DELAY_DESCRIPTORS + 1):
            where = f"delay_import:{index}"
            if index == MAX_DELAY_DESCRIPTORS:
                self.issue("delay_import_listing_capped", "delay_import")
                break
            raw = self.u_rva("IIIIIIII", rva + 32 * index)
            if raw is None:
                self.issue("delay_import_descriptor_unmapped", where)
                break
            attributes, name, _module_handle, _iat, name_table = raw[:5]
            if not any(raw) or name == 0:
                break
            if not attributes & 1:
                # Pre-VC7 descriptors hold virtual addresses, not RVAs.
                name -= self.image_base
                name_table -= self.image_base
            functions, count = self._thunks(name_table, where, budget)
            modules.append(
                {
                    **self.ascii_at_rva(name, where),
                    "attributes": attributes,
                    "function_count": count,
                    "functions": functions,
                }
            )
        return modules

    def _exports(self, directories: list[dict[str, Any]]) -> dict[str, Any] | None:
        located = self.directory(directories, _EXPORT)
        if located is None:
            return None
        rva, size = located
        raw = self.u_rva("IIHHIIIIIII", rva)
        if raw is None:
            self.issue("export_directory_unmapped", "export")
            return {"name": None, "functions": []}
        (
            _characteristics, time_date_stamp, major, minor, name_rva, base,
            number_of_functions, number_of_names, functions_rva, names_rva, ordinals_rva,
        ) = raw
        names: dict[int, list[dict[str, Any]]] = {}
        for index in range(min(number_of_names, MAX_EXPORTS_LISTED)):
            name_entry = self.u_rva("I", names_rva + 4 * index)
            ordinal_entry = self.u_rva("H", ordinals_rva + 2 * index)
            if name_entry is None or ordinal_entry is None:
                self.issue("export_name_table_unmapped", "export")
                break
            names.setdefault(ordinal_entry[0], []).append(
                self.ascii_at_rva(name_entry[0], "export")
            )
        listed = min(number_of_functions, MAX_EXPORTS_LISTED)
        if number_of_functions > MAX_EXPORTS_LISTED or number_of_names > MAX_EXPORTS_LISTED:
            self.issue("export_listing_capped", "export")
        exports = []
        for index in range(listed):
            function = self.u_rva("I", functions_rva + 4 * index)
            if function is None:
                self.issue("export_address_table_unmapped", "export")
                break
            (function_rva,) = function
            if function_rva == 0:
                continue
            entry: dict[str, Any] = {
                "ordinal": base + index,
                "names": [item.get("name") for item in names.get(index, [])],
                "rva": function_rva,
                "forwarder": None,
            }
            if rva <= function_rva < rva + size:
                entry["forwarder"] = self.ascii_at_rva(function_rva, "export").get("name")
            exports.append(entry)
        return {
            **self.ascii_at_rva(name_rva, "export"),
            "time_date_stamp": time_date_stamp,
            "version": [major, minor],
            "ordinal_base": base,
            "number_of_functions": number_of_functions,
            "number_of_names": number_of_names,
            "functions": exports,
        }

    # -- debug and TLS ------------------------------------------------------

    def _debug(self, directories: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
        located = self.directory(directories, _DEBUG)
        if located is None:
            return None
        rva, size = located
        count = size // 28
        if count > MAX_DEBUG_ENTRIES:
            self.issue("debug_listing_capped", "debug")
            count = MAX_DEBUG_ENTRIES
        entries: list[dict[str, Any]] = []
        for index in range(count):
            raw = self.u_rva("IIHHIIII", rva + 28 * index)
            if raw is None:
                self.issue("debug_directory_unmapped", f"debug:{index}")
                break
            _chars, stamp, major, minor, debug_type, data_size, data_rva, pointer = raw
            entry: dict[str, Any] = {
                "type": debug_type,
                "type_name": _DEBUG_TYPES.get(debug_type),
                "time_date_stamp": stamp,
                "version": [major, minor],
                "size_of_data": data_size,
                "address_of_raw_data": data_rva,
                "pointer_to_raw_data": pointer,
            }
            if debug_type == _DEBUG_CODEVIEW:
                if pointer == 0 and data_rva:
                    mapped = self.map_rva(data_rva)
                    pointer = mapped[0] if mapped else 0
                entry["codeview"] = self._codeview(pointer, data_size, f"debug:{index}")
            entries.append(entry)
        return entries

    def _codeview(self, pointer: int, data_size: int, where: str) -> dict[str, Any] | None:
        if pointer == 0 or pointer + data_size > self.size or data_size < 4:
            self.issue("codeview_out_of_bounds", where)
            return None
        blob = self.data[pointer : pointer + min(data_size, 24 + MAX_NAME_BYTES + 1)]
        if blob[:4] == b"RSDS" and len(blob) >= 24:
            path = blob[24:].split(b"\x00", 1)[0]
            return {
                "format": "RSDS",
                "guid": _guid(blob[4:20]),
                "age": struct.unpack_from("<I", blob, 20)[0],
                "pdb_path": decode_name(path[:MAX_NAME_BYTES], len(path) > MAX_NAME_BYTES),
            }
        if blob[:4] == b"NB10" and len(blob) >= 16:
            path = blob[16:].split(b"\x00", 1)[0]
            return {
                "format": "NB10",
                "signature": struct.unpack_from("<I", blob, 8)[0],
                "age": struct.unpack_from("<I", blob, 12)[0],
                "pdb_path": decode_name(path[:MAX_NAME_BYTES], len(path) > MAX_NAME_BYTES),
            }
        return {"format": None, "signature_hex": blob[:4].hex()}

    def _tls(self, directories: list[dict[str, Any]]) -> dict[str, Any] | None:
        located = self.directory(directories, _TLS)
        if located is None:
            return None
        rva, _ = located
        raw = self.u_rva("QQQQII" if self.is_plus else "IIIIII", rva)
        if raw is None:
            self.issue("tls_directory_unmapped", "tls")
            return None
        start, end, index_address, callbacks_va, zero_fill, characteristics = raw
        callbacks: list[dict[str, Any]] = []
        truncated = False
        if callbacks_va:
            width = 8 if self.is_plus else 4
            table_rva = callbacks_va - self.image_base
            for index in range(MAX_TLS_CALLBACKS + 1):
                if index == MAX_TLS_CALLBACKS:
                    truncated = True
                    self.issue("tls_callback_listing_capped", "tls")
                    break
                entry = self.u_rva("Q" if self.is_plus else "I", table_rva + index * width)
                if entry is None:
                    self.issue("tls_callback_table_unmapped", "tls")
                    break
                (callback_va,) = entry
                if callback_va == 0:
                    break
                callback_rva = callback_va - self.image_base
                section = self.section_of(callback_rva)
                callbacks.append(
                    {
                        "va": callback_va,
                        "rva": callback_rva,
                        "section_name": section.get("name") if section else None,
                    }
                )
        return {
            "start_address_of_raw_data": start,
            "end_address_of_raw_data": end,
            "address_of_index": index_address,
            "address_of_callbacks": callbacks_va,
            "size_of_zero_fill": zero_fill,
            "characteristics": characteristics,
            "callbacks": callbacks,
            "callbacks_truncated": truncated,
        }

    # -- resources ----------------------------------------------------------

    def _resources(self, directories: list[dict[str, Any]]) -> dict[str, Any] | None:
        located = self.directory(directories, _RESOURCE)
        if located is None:
            return None
        rva, _ = located
        mapped = self.map_rva(rva)
        if mapped is None:
            self.issue("resource_directory_unmapped", "resource")
            return None
        base, region_end = mapped
        leaves: list[dict[str, Any]] = []
        visited: set[int] = set()

        def entry_name(value: int) -> dict[str, Any]:
            if not value & 0x80000000:
                return {"id": value & 0xFFFF}
            offset = base + (value & 0x7FFFFFFF)
            if offset + 2 > region_end:
                self.issue("resource_name_out_of_bounds", "resource")
                return {"name": None}
            (length,) = struct.unpack_from("<H", self.data, offset)
            raw = self.data[offset + 2 : min(offset + 2 + 2 * length, region_end)]
            try:
                return {"name": raw.decode("utf-16-le")[:MAX_NAME_BYTES]}
            except UnicodeDecodeError:
                return {"name": None, "name_hex": raw[:MAX_NAME_BYTES].hex()}

        def walk(relative: int, depth: int, path: list[dict[str, Any]]) -> None:
            if relative in visited:
                self.issue("resource_directory_cycle", "resource")
                return
            visited.add(relative)
            header = base + relative
            if header + 16 > region_end:
                self.issue("resource_directory_out_of_bounds", "resource")
                return
            named, ids = struct.unpack_from("<HH", self.data, header + 12)
            for index in range(named + ids):
                if len(leaves) >= MAX_RESOURCE_LEAVES:
                    self.issue("resource_leaf_listing_capped", "resource")
                    return
                entry_offset = header + 16 + 8 * index
                if entry_offset + 8 > region_end:
                    self.issue("resource_entry_out_of_bounds", "resource")
                    return
                name_value, target = struct.unpack_from("<II", self.data, entry_offset)
                step = [*path, entry_name(name_value)]
                if target & 0x80000000:
                    if depth + 1 >= MAX_RESOURCE_DEPTH:
                        self.issue("resource_tree_too_deep", "resource")
                        continue
                    walk(target & 0x7FFFFFFF, depth + 1, step)
                    continue
                data_entry = base + target
                if data_entry + 16 > region_end:
                    self.issue("resource_data_entry_out_of_bounds", "resource")
                    continue
                data_rva, data_size, codepage, _ = struct.unpack_from(
                    "<IIII", self.data, data_entry
                )
                leaves.append({"path": step, "rva": data_rva, "size": data_size,
                               "codepage": codepage})

        walk(0, 0, [])
        types: dict[str, dict[str, Any]] = {}
        listed: list[dict[str, Any]] = []
        version_info = None
        for leaf in leaves:
            type_entry = leaf["path"][0]
            type_id = type_entry.get("id")
            label = _RESOURCE_TYPES.get(type_id) if type_id is not None else type_entry.get("name")
            key = f"id:{type_id}" if type_id is not None else f"name:{label}"
            summary = types.setdefault(
                key, {"type_id": type_id, "type_label": label, "count": 0, "total_size": 0}
            )
            summary["count"] += 1
            summary["total_size"] += leaf["size"]
            mapped_leaf = self.map_rva(leaf["rva"])
            in_file = mapped_leaf is not None and mapped_leaf[0] + leaf["size"] <= mapped_leaf[1]
            if len(listed) < MAX_RESOURCE_LEAVES_LISTED:
                record = {
                    "type_id": type_id,
                    "type_label": label,
                    "name": leaf["path"][1] if len(leaf["path"]) > 1 else None,
                    "language": leaf["path"][2].get("id") if len(leaf["path"]) > 2 else None,
                    "rva": leaf["rva"],
                    "size": leaf["size"],
                    "codepage": leaf["codepage"],
                    "in_file": in_file,
                    "sha256": None,
                    "entropy_bits_per_byte": None,
                }
                if in_file and leaf["size"] and mapped_leaf and self.budget.take(leaf["size"]):
                    record.update(measure_range(self.view, mapped_leaf[0], leaf["size"]))
                listed.append(record)
            if type_id == _RT_VERSION and version_info is None and in_file and mapped_leaf:
                blob = self.data[mapped_leaf[0] : mapped_leaf[0] + leaf["size"]]
                version_info = self._version_info(blob)
        if len(leaves) > MAX_RESOURCE_LEAVES_LISTED:
            self.issue("resource_listing_capped", "resource")
        return {
            "leaf_count": len(leaves),
            "types": [types[key] for key in sorted(types)],
            "leaves": listed,
            "version_info": version_info,
        }

    def _version_node(self, blob: bytes, position: int, end: int, depth: int) -> dict[str, Any]:
        if depth > MAX_VERSION_DEPTH or position + 6 > end:
            raise ValueError("version_node_out_of_bounds")
        length, value_length, value_type = struct.unpack_from("<HHH", blob, position)
        node_end = position + length
        if length < 6 or node_end > end:
            raise ValueError("version_node_length_invalid")
        key_end = position + 6
        while key_end + 1 < node_end and blob[key_end : key_end + 2] != b"\x00\x00":
            key_end += 2
        if key_end + 1 >= node_end:
            raise ValueError("version_key_unterminated")
        key = blob[position + 6 : key_end].decode("utf-16-le")
        value_start = _align4(key_end + 2)
        value_bytes = value_length * 2 if value_type == 1 else value_length
        value = blob[value_start : min(value_start + value_bytes, node_end)]
        children: list[dict[str, Any]] = []
        child = _align4(value_start + value_bytes)
        while child + 6 <= node_end and len(children) < MAX_VERSION_STRINGS:
            node = self._version_node(blob, child, node_end, depth + 1)
            children.append(node)
            child = _align4(child + node["length"])
        return {"key": key, "type": value_type, "value": value, "value_start": value_start,
                "end": node_end, "length": length, "children": children, "blob": blob}

    def _version_info(self, blob: bytes) -> dict[str, Any] | None:
        try:
            root = self._version_node(blob, 0, len(blob), 0)
        except (ValueError, struct.error, UnicodeDecodeError):
            self.issue("version_info_malformed", "resource")
            return None
        fixed = None
        value = root["value"]
        if len(value) >= 52 and struct.unpack_from("<I", value, 0)[0] == _FIXED_FILE_INFO_SIGNATURE:
            (_sig, struct_version, file_ms, file_ls, product_ms, product_ls, _mask, file_flags,
             file_os, file_type, file_subtype, _date_ms, _date_ls) = struct.unpack_from(
                "<13I", value, 0
            )
            fixed = {
                "struct_version": struct_version,
                "file_version": f"{file_ms >> 16}.{file_ms & 0xFFFF}.{file_ls >> 16}."
                f"{file_ls & 0xFFFF}",
                "product_version": f"{product_ms >> 16}.{product_ms & 0xFFFF}."
                f"{product_ls >> 16}.{product_ls & 0xFFFF}",
                "file_flags": file_flags,
                "file_os": file_os,
                "file_type": file_type,
                "file_subtype": file_subtype,
            }
        strings: list[dict[str, Any]] = []
        translations: list[dict[str, int]] = []
        for child in root["children"]:
            if child["key"] == "StringFileInfo":
                for table in child["children"]:
                    for item in table["children"]:
                        if len(strings) >= MAX_VERSION_STRINGS:
                            self.issue("version_string_listing_capped", "resource")
                            break
                        raw = item["blob"][item["value_start"] : item["end"]]
                        text = _utf16_until_nul(raw)
                        record: dict[str, Any] = {"table": table["key"], "key": item["key"]}
                        if text is None:
                            record.update(
                                {"value": None, "value_hex": raw[:MAX_VERSION_TEXT].hex()}
                            )
                        else:
                            record["value"] = text[:MAX_VERSION_TEXT]
                        strings.append(record)
            elif child["key"] == "VarFileInfo":
                for var in child["children"]:
                    if var["key"] != "Translation":
                        continue
                    pairs = var["value"]
                    for offset in range(0, len(pairs) - 3, 4):
                        language, codepage = struct.unpack_from("<HH", pairs, offset)
                        translations.append({"language": language, "codepage": codepage})
        return {"fixed": fixed, "strings": strings, "translations": translations}

    # -- certificate table and overlay --------------------------------------

    def _certificates(self, directories: list[dict[str, Any]]) -> dict[str, Any] | None:
        located = self.directory(directories, _SECURITY)
        if located is None:
            return None
        offset, size = located  # a FILE offset, not an RVA
        in_file = offset + size <= self.size
        record: dict[str, Any] = {"offset": offset, "size": size, "in_file": in_file,
                                  "entries": [], "verified": False}
        if not in_file:
            self.issue("certificate_table_out_of_bounds", "directory:4")
            return record
        position, end = offset, offset + size
        while position + 8 <= end and len(record["entries"]) < MAX_CERTIFICATES:
            length, revision, certificate_type = struct.unpack_from("<IHH", self.data, position)
            if length < 8 or position + length > end:
                self.issue("certificate_entry_malformed", "directory:4")
                break
            record["entries"].append(
                {
                    "length": length,
                    "revision": revision,
                    "certificate_type": certificate_type,
                    "certificate_type_name": _CERTIFICATE_TYPES.get(certificate_type),
                    "sha256": sha256_hex(self.view[position + 8 : position + length]),
                }
            )
            position += (length + 7) & ~7
        return record

    def _overlay(self, certificates: dict[str, Any] | None) -> dict[str, Any] | None:
        end = min(self.size_of_headers, self.size)
        for _, _, pointer, raw_size, _ in self.raw_sections:
            if raw_size:
                end = max(end, pointer + raw_size)
        if end >= self.size:
            return None
        size = self.size - end
        record: dict[str, Any] = {
            "offset": end,
            "size": size,
            "contains_certificate_table": bool(
                certificates and certificates["in_file"] and certificates["offset"] >= end
            ),
            "sha256": None,
            "entropy_bits_per_byte": None,
        }
        if self.budget.take(size):
            record.update(measure_range(self.view, end, size))
        return record


def _utf16_until_nul(raw: bytes) -> str | None:
    for index in range(0, len(raw) - 1, 2):
        if raw[index] == 0 and raw[index + 1] == 0:
            raw = raw[:index]
            break
    else:
        raw = raw[: len(raw) - len(raw) % 2]
    try:
        return raw.decode("utf-16-le")
    except UnicodeDecodeError:
        return None


def parse_pe(data: bytes) -> tuple[dict[str, Any], list[dict[str, str]]] | None:
    """Parse a PE image; ``None`` when MZ has no PE signature."""
    parser = _Pe(data)
    fields = parser.parse()
    if fields is None:
        return None
    return fields, parser.issues
