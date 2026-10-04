"""Bounded, read-only ELF parser for static triage.

The data model follows the loader abstraction of Andriesse, *Practical
Binary Analysis* (ch. 4: a binary with sections and symbols), re-implemented
directly over the format described in ch. 2 with the standard library only.
It deliberately departs from that loader where a forensic boundary needs
different behavior:

- every section, segment, symbol binding and note is kept; nothing is dropped
  for not being code, data, or a function;
- an unreadable sub-structure is recorded as a parse issue, never as an empty
  table (the book's loader ignores symbol-table failures, so "no symbols" and
  "could not read symbols" look the same);
- offsets and sizes declared by the file are never trusted for allocation:
  every read is a bounds-checked view of the already size-bounded input;
- the architecture is recorded, not required: an unknown ``e_machine`` yields
  a null name, not a failure;
- nothing is disassembled, relocated, loaded or executed (ADR-0003).

Only a header that cannot be parsed at all raises :class:`ElfFormatError`.
Everything below the header degrades into ``issues`` so that the caller can
emit an honest partial observation.
"""

from __future__ import annotations

import struct
from typing import Any

from tools.binary_static.measure import MeasurementBudget, measure_range

ELF_MAGIC = b"\x7fELF"

MAX_SECTIONS = 4096
MAX_SEGMENTS = 512
MAX_SYMBOL_TABLES = 8
MAX_SYMBOLS_LISTED = 4096
MAX_SYMBOL_ENTRIES_SCANNED = 2_000_000
MAX_NAME_BYTES = 1024
MAX_NOTES = 64
MAX_NOTE_OWNER_BYTES = 64
MAX_NOTE_DESC_BYTES = 256
MAX_DYNAMIC_ENTRIES = 4096
MAX_DYNAMIC_STRINGS = 256
MAX_COMMENT_STRINGS = 16
MAX_COMMENT_BYTES = 256
MAX_ISSUES = 256
MAX_MODINFO_RECORDS = 256
MAX_MODINFO_VALUE = 1024
MAX_VERSION_NEEDS = 256

LIMITS = {
    "max_sections": MAX_SECTIONS,
    "max_segments": MAX_SEGMENTS,
    "max_symbol_tables": MAX_SYMBOL_TABLES,
    "max_symbols_listed": MAX_SYMBOLS_LISTED,
    "max_symbol_entries_scanned": MAX_SYMBOL_ENTRIES_SCANNED,
    "max_name_bytes": MAX_NAME_BYTES,
    "max_notes": MAX_NOTES,
    "max_note_desc_bytes": MAX_NOTE_DESC_BYTES,
    "max_dynamic_entries": MAX_DYNAMIC_ENTRIES,
    "max_comment_strings": MAX_COMMENT_STRINGS,
    "max_modinfo_records": MAX_MODINFO_RECORDS,
    "max_version_needs": MAX_VERSION_NEEDS,
}

_ELF_TYPES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
_OSABI = {
    0: "SYSV", 1: "HPUX", 2: "NETBSD", 3: "GNU", 6: "SOLARIS", 7: "AIX", 8: "IRIX",
    9: "FREEBSD", 10: "TRU64", 12: "OPENBSD", 97: "ARM", 255: "STANDALONE",
}
_MACHINES = {
    0: "NONE", 2: "SPARC", 3: "X86", 8: "MIPS", 20: "PPC", 21: "PPC64", 22: "S390",
    40: "ARM", 43: "SPARCV9", 50: "IA_64", 62: "X86_64", 183: "AARCH64", 243: "RISCV",
    247: "BPF", 258: "LOONGARCH",
}
_SECTION_TYPES = {
    0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH", 6: "DYNAMIC",
    7: "NOTE", 8: "NOBITS", 9: "REL", 10: "SHLIB", 11: "DYNSYM", 14: "INIT_ARRAY",
    15: "FINI_ARRAY", 16: "PREINIT_ARRAY", 17: "GROUP", 18: "SYMTAB_SHNDX",
    0x6FFFFFF5: "GNU_ATTRIBUTES", 0x6FFFFFF6: "GNU_HASH", 0x6FFFFFF7: "GNU_LIBLIST",
    0x6FFFFFFD: "GNU_VERDEF", 0x6FFFFFFE: "GNU_VERNEED", 0x6FFFFFFF: "GNU_VERSYM",
}
_SECTION_FLAGS = (
    (0x1, "WRITE"), (0x2, "ALLOC"), (0x4, "EXECINSTR"), (0x10, "MERGE"), (0x20, "STRINGS"),
    (0x40, "INFO_LINK"), (0x80, "LINK_ORDER"), (0x100, "OS_NONCONFORMING"), (0x200, "GROUP"),
    (0x400, "TLS"), (0x800, "COMPRESSED"),
)
_SEGMENT_TYPES = {
    0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 5: "SHLIB", 6: "PHDR", 7: "TLS",
    0x6474E550: "GNU_EH_FRAME", 0x6474E551: "GNU_STACK", 0x6474E552: "GNU_RELRO",
    0x6474E553: "GNU_PROPERTY",
}
_SEGMENT_FLAGS = ((0x4, "R"), (0x2, "W"), (0x1, "X"))
_SYMBOL_BINDS = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK", 10: "GNU_UNIQUE"}
_SYMBOL_TYPES = {
    0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE", 5: "COMMON", 6: "TLS",
    10: "GNU_IFUNC",
}
_VISIBILITY = {0: "DEFAULT", 1: "INTERNAL", 2: "HIDDEN", 3: "PROTECTED"}

_SHT_NULL, _SHT_SYMTAB, _SHT_STRTAB, _SHT_DYNAMIC, _SHT_NOTE, _SHT_NOBITS, _SHT_DYNSYM = (
    0, 2, 3, 6, 7, 8, 11,
)
_PT_LOAD, _PT_DYNAMIC, _PT_INTERP, _PT_NOTE = 1, 2, 3, 4
_SHT_GNU_VERNEED = 0x6FFFFFFE
_SHF_ALLOC, _SHF_TLS = 0x2, 0x400
_GNU_ABI_OS = {0: "LINUX", 1: "HURD", 2: "SOLARIS", 3: "FREEBSD"}
_SHN_XINDEX = 0xFFFF
_PN_XNUM = 0xFFFF
_DT_NULL, _DT_NEEDED, _DT_STRTAB, _DT_STRSZ, _DT_SONAME, _DT_RPATH = 0, 1, 5, 10, 14, 15
_DT_RUNPATH, _DT_FLAGS, _DT_FLAGS_1 = 29, 30, 0x6FFFFFFB


class ElfFormatError(ValueError):
    """The ELF header cannot be parsed; nothing below it is trustworthy."""


def _flag_names(value: int, table: tuple[tuple[int, str], ...]) -> dict[str, Any]:
    names = [name for bit, name in table if value & bit]
    known = 0
    for bit, _ in table:
        known |= bit
    result: dict[str, Any] = {"names": names}
    if value & ~known:
        result["unknown_bits"] = value & ~known
    return result


class _Elf:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.view = memoryview(data)
        self.size = len(data)
        self.issues: list[dict[str, str]] = []
        self._issue_overflow = False
        self._structs: dict[str, struct.Struct] = {}
        self.endian = "<"
        self.is64 = False

    # -- primitives ---------------------------------------------------------

    def issue(self, code: str, where: str = "") -> None:
        if len(self.issues) >= MAX_ISSUES:
            if not self._issue_overflow:
                self._issue_overflow = True
                self.issues.append({"code": "issue_limit_reached", "where": ""})
            return
        self.issues.append({"code": code, "where": where})

    def in_bounds(self, offset: int, length: int) -> bool:
        return 0 <= offset and 0 <= length and offset + length <= self.size

    def unpack(self, fmt: str, offset: int) -> tuple[Any, ...] | None:
        packer = self._structs.get(fmt)
        if packer is None:
            packer = struct.Struct(self.endian + fmt)
            self._structs[fmt] = packer
        if not self.in_bounds(offset, packer.size):
            return None
        return packer.unpack_from(self.data, offset)

    def cstring(
        self, table_offset: int, table_size: int, index: int, where: str
    ) -> dict[str, Any]:
        """Read a NUL-terminated name from a bounded string table."""
        if index >= table_size:
            self.issue("name_offset_out_of_bounds", where)
            return {"name": None}
        start = table_offset + index
        end = table_offset + table_size
        terminator = self.data.find(b"\x00", start, min(end, start + MAX_NAME_BYTES + 1))
        truncated = False
        if terminator == -1:
            if end - start > MAX_NAME_BYTES:
                terminator = start + MAX_NAME_BYTES
                truncated = True
                self.issue("name_truncated", where)
            else:
                self.issue("unterminated_name", where)
                return {"name": None}
        return decode_name(self.data[start:terminator], truncated)

    # -- header -------------------------------------------------------------

    def parse(self) -> dict[str, Any]:
        if self.size < 16 or self.data[:4] != ELF_MAGIC:
            raise ElfFormatError("not_elf")
        ei_class, ei_data, ei_version, ei_osabi, ei_abiversion = self.data[4:9]
        if ei_class not in (1, 2):
            raise ElfFormatError("unsupported_elf_class")
        if ei_data not in (1, 2):
            raise ElfFormatError("unsupported_elf_data_encoding")
        self.endian = "<" if ei_data == 1 else ">"
        self.is64 = ei_class == 2
        header = self.unpack("HHIQQQIHHHHHH" if self.is64 else "HHIIIIIHHHHHH", 16)
        if header is None:
            raise ElfFormatError("truncated_elf_header")
        (
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
            e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx,
        ) = header
        if ei_version != 1 or e_version != 1:
            self.issue("unexpected_elf_version", "header")
        if e_ehsize != (64 if self.is64 else 52):
            self.issue("nonstandard_header_size", "header")

        extended: list[str] = []
        sections, shnum, shstrndx, phnum = self._sections(
            e_shoff, e_shentsize, e_shnum, e_shstrndx, e_phnum, extended
        )
        segments = self._segments(e_phoff, e_phentsize, phnum)
        budget = MeasurementBudget(4 * max(self.size, 1))
        self._measure(sections, segments, budget)
        self._layout_checks(e_shoff, e_phoff, sections, segments)

        result = {
            "ident": {
                "class": 64 if self.is64 else 32,
                "data": "little" if ei_data == 1 else "big",
                "version": ei_version,
                "osabi": ei_osabi,
                "osabi_name": _OSABI.get(ei_osabi),
                "abiversion": ei_abiversion,
            },
            "header": {
                "type": e_type,
                "type_name": _ELF_TYPES.get(e_type),
                "machine": e_machine,
                "machine_name": _MACHINES.get(e_machine),
                "version": e_version,
                "entry": e_entry,
                "phoff": e_phoff,
                "shoff": e_shoff,
                "flags": e_flags,
                "ehsize": e_ehsize,
                "phentsize": e_phentsize,
                "phnum": phnum,
                "shentsize": e_shentsize,
                "shnum": shnum,
                "shstrndx": shstrndx,
                "extended_numbering": sorted(extended),
            },
            "sections": [self._section_record(s) for s in sections],
            "segments": [self._segment_record(s) for s in segments],
            "entry_point": self._entry_point(e_type, e_entry, sections, segments),
            "interpreter": self._interpreter(segments),
            "dynamic": self._dynamic(sections, segments),
            "symbol_tables": self._symbol_tables(sections),
            "version_needs": self._version_needs(sections),
            "notes": self._notes(sections, segments),
            "comment": self._comment(sections),
            "modinfo": self._modinfo(sections),
            "limits": dict(LIMITS),
        }
        return result

    # -- loader view versus section view ------------------------------------

    def _layout_checks(
        self,
        e_shoff: int,
        e_phoff: int,
        sections: list[dict[str, Any]],
        segments: list[dict[str, Any]],
    ) -> None:
        """Compare the section table with what the loader maps.

        The loader uses only program headers; section headers can be shifted
        or rewritten while the binary still runs. Each section that should be
        loaded records whether a PT_LOAD segment maps it at the same file
        offset, so a disagreement between the two views is visible instead of
        silently trusted.
        """
        word = 8 if self.is64 else 4
        if e_shoff % word:
            self.issue("section_table_misaligned", "header")
        if e_phoff % word:
            self.issue("program_header_table_misaligned", "header")
        loads = [s for s in segments if s["type"] == _PT_LOAD]
        for section in sections:
            section["matches_load_segment"] = None
            align = section["addralign"]
            if section["in_file"] and align > 1 and section["offset"] % align:
                self.issue("section_offset_misaligned", f"section:{section['index']}")
            if not loads or not section["flags"] & _SHF_ALLOC or not section["size"]:
                continue
            if section["type"] == _SHT_NOBITS and section["flags"] & _SHF_TLS:
                continue  # .tbss occupies no address range in a PT_LOAD segment
            start, end = section["addr"], section["addr"] + section["size"]
            matched = False
            for segment in loads:
                if not segment["vaddr"] <= start or end > segment["vaddr"] + segment["memsz"]:
                    continue
                if section["type"] == _SHT_NOBITS:
                    matched = True
                else:
                    matched = section["offset"] == segment["offset"] + (start - segment["vaddr"])
                if matched:
                    break
            section["matches_load_segment"] = matched
            if not matched:
                self.issue("section_not_mapped_as_declared", f"section:{section['index']}")

    def _entry_point(
        self,
        e_type: int,
        entry: int,
        sections: list[dict[str, Any]],
        segments: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        if e_type not in (2, 3) or entry == 0:
            return None
        segment = next(
            (
                s for s in segments
                if s["type"] == _PT_LOAD and s["vaddr"] <= entry < s["vaddr"] + s["memsz"]
            ),
            None,
        )
        section = next(
            (
                s for s in sections
                if s["flags"] & _SHF_ALLOC and s["size"]
                and s["addr"] <= entry < s["addr"] + s["size"]
            ),
            None,
        )
        return {
            "vaddr": entry,
            "segment_index": segment["index"] if segment else None,
            "segment_flag_names": (
                _flag_names(segment["flags"], _SEGMENT_FLAGS)["names"] if segment else None
            ),
            "section_index": section["index"] if section else None,
            "section_name": section["name"].get("name") if section else None,
        }

    # -- Linux and GNU structures --------------------------------------------

    def _modinfo(self, sections: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
        """`key=value` records of a Linux kernel module's .modinfo section."""
        for section in sections:
            if section["name"].get("name") != ".modinfo" or not section["in_file"]:
                continue
            raw = self.data[section["offset"] : section["offset"] + section["size"]]
            records: list[dict[str, Any]] = []
            for part in raw.split(b"\x00"):
                if not part:
                    continue
                if len(records) >= MAX_MODINFO_RECORDS:
                    self.issue("modinfo_listing_capped", f"section:{section['index']}")
                    break
                key, separator, value = part.partition(b"=")
                record = {
                    "key": decode_name(key[:MAX_NAME_BYTES]).get("name"),
                    **decode_value(value[:MAX_MODINFO_VALUE], len(value) > MAX_MODINFO_VALUE),
                }
                if not separator:
                    record["malformed"] = True
                records.append(record)
            return records
        return None

    def _version_needs(self, sections: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
        """GNU symbol-version requirements (`SHT_GNU_verneed`), as readelf -V shows."""
        tables = [s for s in sections if s["type"] == _SHT_GNU_VERNEED]
        if not tables:
            return None
        table = tables[0]
        where = f"section:{table['index']}"
        if not table["in_file"]:
            self.issue("version_needs_unreadable", where)
            return []
        link = table["link"]
        strtab = None
        if link < len(sections) and sections[link]["in_file"]:
            strtab = (sections[link]["offset"], sections[link]["size"])
        else:
            self.issue("version_needs_string_table_unavailable", where)
        base, end = table["offset"], table["offset"] + table["size"]
        needs: list[dict[str, Any]] = []
        position = base
        for _ in range(min(table["info"] or MAX_VERSION_NEEDS, MAX_VERSION_NEEDS)):
            raw = self.unpack("HHIII", position)
            if raw is None or position + 16 > end:
                self.issue("version_needs_malformed", where)
                break
            _version, count, file_offset, aux_offset, next_offset = raw
            versions: list[dict[str, Any]] = []
            aux = position + aux_offset
            for _ in range(min(count, MAX_VERSION_NEEDS)):
                aux_raw = self.unpack("IHHII", aux)
                if aux_raw is None or aux + 16 > end:
                    self.issue("version_needs_malformed", where)
                    break
                _hash, flags, other, name_offset, aux_next = aux_raw
                name = (
                    self.cstring(strtab[0], strtab[1], name_offset, where)
                    if strtab else {"name": None}
                )
                versions.append({**name, "flags": flags, "index": other})
                if aux_next == 0:
                    break
                aux += aux_next
            file_name = (
                self.cstring(strtab[0], strtab[1], file_offset, where) if strtab else {"name": None}
            )
            needs.append({"file": file_name.get("name"), "versions": versions})
            if next_offset == 0:
                break
            position += next_offset
        return needs

    # -- section and program header tables ----------------------------------

    def _sections(
        self,
        e_shoff: int,
        e_shentsize: int,
        e_shnum: int,
        e_shstrndx: int,
        e_phnum: int,
        extended: list[str],
    ) -> tuple[list[dict[str, Any]], int, int, int]:
        shnum, shstrndx, phnum = e_shnum, e_shstrndx, e_phnum
        sections: list[dict[str, Any]] = []
        if e_shoff == 0:
            if e_shnum:
                self.issue("section_count_without_table", "header")
            return sections, shnum, shstrndx, phnum
        expected = 64 if self.is64 else 40
        if e_shentsize < expected:
            self.issue("section_header_entsize_too_small", "header")
            return sections, shnum, shstrndx, phnum
        if e_shentsize != expected:
            self.issue("nonstandard_section_header_entsize", "header")
        fmt = "IIQQQQIIQQ" if self.is64 else "IIIIIIIIII"
        first = self.unpack(fmt, e_shoff)
        if first is None:
            self.issue("section_table_out_of_bounds", "header")
            return sections, shnum, shstrndx, phnum
        if e_shnum == 0:
            shnum = first[5]
            extended.append("shnum")
        if e_shstrndx == _SHN_XINDEX:
            shstrndx = first[6]
            extended.append("shstrndx")
        if e_phnum == _PN_XNUM:
            phnum = first[7]
            extended.append("phnum")

        available = (self.size - e_shoff) // e_shentsize
        count = min(shnum, available)
        if shnum > available:
            self.issue("section_table_truncated_by_eof", "header")
        if count > MAX_SECTIONS:
            self.issue("section_listing_capped", "header")
            count = MAX_SECTIONS
        for index in range(count):
            raw = self.unpack(fmt, e_shoff + index * e_shentsize)
            if raw is None:  # pragma: no cover - guarded by `available`
                self.issue("section_header_unreadable", f"section:{index}")
                break
            name_off, sh_type, flags, addr, offset, size, link, info, align, entsize = raw
            sections.append(
                {
                    "index": index, "name_offset": name_off, "type": sh_type, "flags": flags,
                    "addr": addr, "offset": offset, "size": size, "link": link, "info": info,
                    "addralign": align, "entsize": entsize,
                }
            )

        names_table = None
        if sections and shstrndx != 0:
            if shstrndx >= len(sections):
                self.issue("section_name_table_index_out_of_range", "header")
            else:
                table = sections[shstrndx]
                if table["type"] != _SHT_STRTAB:
                    self.issue("section_name_table_not_strtab", f"section:{shstrndx}")
                if self.in_bounds(table["offset"], table["size"]):
                    names_table = (table["offset"], table["size"])
                else:
                    self.issue("section_name_table_out_of_bounds", f"section:{shstrndx}")
        for section in sections:
            if names_table is None:
                section["name"] = {"name": None}
            else:
                section["name"] = self.cstring(
                    names_table[0], names_table[1], section["name_offset"],
                    f"section:{section['index']}",
                )
            has_file_data = section["type"] not in (_SHT_NULL, _SHT_NOBITS)
            section["in_file"] = has_file_data and self.in_bounds(
                section["offset"], section["size"]
            )
            if has_file_data and section["size"] and not section["in_file"]:
                self.issue("section_data_out_of_bounds", f"section:{section['index']}")
        return sections, shnum, shstrndx, phnum

    def _segments(self, e_phoff: int, e_phentsize: int, phnum: int) -> list[dict[str, Any]]:
        segments: list[dict[str, Any]] = []
        if e_phoff == 0 or phnum == 0:
            if phnum and e_phoff == 0:
                self.issue("segment_count_without_table", "header")
            return segments
        expected = 56 if self.is64 else 32
        if e_phentsize < expected:
            self.issue("program_header_entsize_too_small", "header")
            return segments
        if e_phentsize != expected:
            self.issue("nonstandard_program_header_entsize", "header")
        if e_phoff >= self.size:
            self.issue("program_header_table_out_of_bounds", "header")
            return segments
        available = (self.size - e_phoff) // e_phentsize
        count = min(phnum, available)
        if phnum > available:
            self.issue("program_header_table_truncated_by_eof", "header")
        if count > MAX_SEGMENTS:
            self.issue("segment_listing_capped", "header")
            count = MAX_SEGMENTS
        for index in range(count):
            offset = e_phoff + index * e_phentsize
            if self.is64:
                raw = self.unpack("IIQQQQQQ", offset)
                if raw is None:  # pragma: no cover - guarded by `available`
                    break
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = raw
            else:
                raw = self.unpack("IIIIIIII", offset)
                if raw is None:  # pragma: no cover - guarded by `available`
                    break
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = raw
            in_file = self.in_bounds(p_offset, p_filesz)
            if p_filesz and not in_file:
                self.issue("segment_data_out_of_bounds", f"segment:{index}")
            segments.append(
                {
                    "index": index, "type": p_type, "flags": p_flags, "offset": p_offset,
                    "vaddr": p_vaddr, "paddr": p_paddr, "filesz": p_filesz, "memsz": p_memsz,
                    "align": p_align, "in_file": in_file,
                }
            )
        return segments

    def _measure(
        self,
        sections: list[dict[str, Any]],
        segments: list[dict[str, Any]],
        budget: MeasurementBudget,
    ) -> None:
        for section in sections:
            section["measurement"] = None
            if section["in_file"] and section["size"]:
                if budget.take(section["size"]):
                    section["measurement"] = measure_range(
                        self.view, section["offset"], section["size"]
                    )
        for segment in segments:
            segment["measurement"] = None
            if segment["type"] == _PT_LOAD and segment["in_file"] and segment["filesz"]:
                if budget.take(segment["filesz"]):
                    segment["measurement"] = measure_range(
                        self.view, segment["offset"], segment["filesz"]
                    )
        if budget.exhausted:
            self.issue("measurement_budget_exhausted", "file")

    @staticmethod
    def _section_record(section: dict[str, Any]) -> dict[str, Any]:
        record = {
            "index": section["index"],
            **section["name"],
            "type": section["type"],
            "type_name": _SECTION_TYPES.get(section["type"]),
            "flags": section["flags"],
            "flag_names": _flag_names(section["flags"], _SECTION_FLAGS),
            "addr": section["addr"],
            "offset": section["offset"],
            "size": section["size"],
            "link": section["link"],
            "info": section["info"],
            "addralign": section["addralign"],
            "entsize": section["entsize"],
            "in_file": section["in_file"],
            "matches_load_segment": section.get("matches_load_segment"),
            "sha256": None,
            "entropy_bits_per_byte": None,
        }
        if section["measurement"] is not None:
            record.update(section["measurement"])
        return record

    @staticmethod
    def _segment_record(segment: dict[str, Any]) -> dict[str, Any]:
        record = {
            "index": segment["index"],
            "type": segment["type"],
            "type_name": _SEGMENT_TYPES.get(segment["type"]),
            "flags": segment["flags"],
            "flag_names": _flag_names(segment["flags"], _SEGMENT_FLAGS),
            "offset": segment["offset"],
            "vaddr": segment["vaddr"],
            "paddr": segment["paddr"],
            "filesz": segment["filesz"],
            "memsz": segment["memsz"],
            "align": segment["align"],
            "in_file": segment["in_file"],
            "sha256": None,
            "entropy_bits_per_byte": None,
        }
        if segment["measurement"] is not None:
            record.update(segment["measurement"])
        return record

    # -- loader-facing structures --------------------------------------------

    def _interpreter(self, segments: list[dict[str, Any]]) -> dict[str, Any] | None:
        interps = [s for s in segments if s["type"] == _PT_INTERP]
        if not interps:
            return None
        if len(interps) > 1:
            self.issue("multiple_interpreter_segments", "segments")
        segment = interps[0]
        where = f"segment:{segment['index']}"
        if not segment["in_file"]:
            return {"name": None}
        raw = self.data[segment["offset"] : segment["offset"] + segment["filesz"]]
        terminator = raw.find(b"\x00")
        if terminator == -1:
            self.issue("unterminated_interpreter", where)
            terminator = len(raw)
        truncated = terminator > MAX_NAME_BYTES
        if truncated:
            self.issue("name_truncated", where)
        return decode_name(raw[: min(terminator, MAX_NAME_BYTES)], truncated)

    def _vaddr_to_offset(self, segments: list[dict[str, Any]], vaddr: int) -> int | None:
        for segment in segments:
            if segment["type"] != _PT_LOAD or not segment["in_file"]:
                continue
            if segment["vaddr"] <= vaddr < segment["vaddr"] + segment["filesz"]:
                return segment["offset"] + (vaddr - segment["vaddr"])
        return None

    def _dynamic(
        self, sections: list[dict[str, Any]], segments: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        dynamic_segments = [s for s in segments if s["type"] == _PT_DYNAMIC]
        dynamic_sections = [s for s in sections if s["type"] == _SHT_DYNAMIC]
        if len(dynamic_segments) > 1:
            self.issue("multiple_dynamic_segments", "segments")
        if dynamic_segments:
            container = dynamic_segments[0]
            source = f"segment:{container['index']}"
            offset, size, in_file = container["offset"], container["filesz"], container["in_file"]
        elif dynamic_sections:
            container = dynamic_sections[0]
            source = f"section:{container['index']}"
            offset, size, in_file = container["offset"], container["size"], container["in_file"]
        else:
            return None
        if not in_file:
            return {"source": source, "entry_count": None}

        entry_size = 16 if self.is64 else 8
        fmt = "qQ" if self.is64 else "iI"
        entries: list[tuple[int, int]] = []
        terminated = False
        for index in range(min(size // entry_size, MAX_DYNAMIC_ENTRIES)):
            raw = self.unpack(fmt, offset + index * entry_size)
            if raw is None:  # pragma: no cover - guarded by in_file
                break
            if raw[0] == _DT_NULL:
                terminated = True
                break
            entries.append(raw)
        if not terminated:
            self.issue("dynamic_table_without_terminator", source)

        values: dict[int, list[int]] = {}
        for tag, value in entries:
            values.setdefault(tag, []).append(value)

        strtab: tuple[int, int] | None = None
        if source.startswith("segment:"):
            if _DT_STRTAB in values and _DT_STRSZ in values:
                table_offset = self._vaddr_to_offset(segments, values[_DT_STRTAB][0])
                table_size = values[_DT_STRSZ][0]
                if table_offset is not None and self.in_bounds(table_offset, table_size):
                    strtab = (table_offset, table_size)
        else:
            link = container["link"]
            if link < len(sections) and sections[link]["in_file"]:
                strtab = (sections[link]["offset"], sections[link]["size"])
        if strtab is None and any(
            tag in values for tag in (_DT_NEEDED, _DT_SONAME, _DT_RPATH, _DT_RUNPATH)
        ):
            self.issue("dynamic_string_table_unavailable", source)

        def strings(tag: int) -> list[dict[str, Any]]:
            found = values.get(tag, [])
            if len(found) > MAX_DYNAMIC_STRINGS:
                self.issue("dynamic_string_listing_capped", source)
                found = found[:MAX_DYNAMIC_STRINGS]
            if strtab is None:
                return [{"name": None} for _ in found]
            return [self.cstring(strtab[0], strtab[1], value, source) for value in found]

        return {
            "source": source,
            "entry_count": len(entries),
            "needed": strings(_DT_NEEDED),
            "soname": strings(_DT_SONAME),
            "rpath": strings(_DT_RPATH),
            "runpath": strings(_DT_RUNPATH),
            "flags": values.get(_DT_FLAGS, [None])[0],
            "flags_1": values.get(_DT_FLAGS_1, [None])[0],
        }

    def _symbol_tables(self, sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
        tables = [s for s in sections if s["type"] in (_SHT_SYMTAB, _SHT_DYNSYM)]
        if len(tables) > MAX_SYMBOL_TABLES:
            self.issue("symbol_table_listing_capped", "sections")
            tables = tables[:MAX_SYMBOL_TABLES]
        expected = 24 if self.is64 else 16
        fmt = "IBBHQQ" if self.is64 else "IIIBBH"
        scan_budget = MAX_SYMBOL_ENTRIES_SCANNED
        listed_total = 0
        results: list[dict[str, Any]] = []
        for table in tables:
            where = f"section:{table['index']}"
            record: dict[str, Any] = {
                "section_index": table["index"],
                "kind": "symtab" if table["type"] == _SHT_SYMTAB else "dynsym",
                "entry_count": None,
                "scanned_count": 0,
                "bind_counts": {},
                "type_counts": {},
                "undefined_count": 0,
                "listed_count": 0,
                "symbols": [],
            }
            results.append(record)
            stride = table["entsize"]
            if stride == 0:
                self.issue("symbol_table_entsize_zero", where)
                stride = expected
            elif stride < expected:
                self.issue("symbol_table_entsize_too_small", where)
                continue
            elif stride != expected:
                self.issue("nonstandard_symbol_entsize", where)
            if not table["in_file"]:
                self.issue("symbol_table_unreadable", where)
                continue
            if table["size"] % stride:
                self.issue("symbol_table_size_not_multiple_of_entsize", where)
            count = table["size"] // stride
            record["entry_count"] = count
            scanned = min(count, scan_budget)
            if scanned < count:
                self.issue("symbol_scan_budget_exhausted", where)
            scan_budget -= scanned
            record["scanned_count"] = scanned

            strtab = None
            link = table["link"]
            if link < len(sections) and sections[link]["in_file"]:
                strtab = (sections[link]["offset"], sections[link]["size"])
            else:
                self.issue("symbol_string_table_unavailable", where)

            binds: dict[str, int] = {}
            types: dict[str, int] = {}
            undefined = 0
            capped = False
            packer = struct.Struct(self.endian + fmt)
            base = table["offset"]
            # Both paths stay inside [base, base + size): `scanned` entries of
            # `stride` bytes each, and the table range is already in_file.
            if stride == packer.size:
                rows = packer.iter_unpack(self.view[base : base + scanned * stride])
            else:
                rows = (packer.unpack_from(self.data, base + i * stride) for i in range(scanned))
            for index, raw in enumerate(rows):
                if self.is64:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = raw
                else:
                    st_name, st_value, st_size, st_info, st_other, st_shndx = raw
                bind, sym_type = st_info >> 4, st_info & 0xF
                bind_key = _SYMBOL_BINDS.get(bind, "OTHER")
                type_key = _SYMBOL_TYPES.get(sym_type, "OTHER")
                binds[bind_key] = binds.get(bind_key, 0) + 1
                types[type_key] = types.get(type_key, 0) + 1
                is_undefined = index != 0 and st_shndx == 0
                if is_undefined:
                    undefined += 1
                if index == 0 or bind == 0:
                    continue
                if listed_total >= MAX_SYMBOLS_LISTED:
                    capped = True
                    continue
                name = (
                    self.cstring(strtab[0], strtab[1], st_name, where)
                    if strtab is not None
                    else {"name": None}
                )
                record["symbols"].append(
                    {
                        "index": index,
                        **name,
                        "value": st_value,
                        "size": st_size,
                        "bind": bind,
                        "bind_name": _SYMBOL_BINDS.get(bind),
                        "type": sym_type,
                        "type_name": _SYMBOL_TYPES.get(sym_type),
                        "visibility": _VISIBILITY.get(st_other & 0x3),
                        "shndx": st_shndx,
                        "undefined": is_undefined,
                    }
                )
                listed_total += 1
            if capped:
                self.issue("symbol_listing_capped", where)
            record["bind_counts"] = binds
            record["type_counts"] = types
            record["undefined_count"] = undefined
            record["listed_count"] = len(record["symbols"])
        return results

    def _notes(
        self, sections: list[dict[str, Any]], segments: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        containers = [
            (f"section:{s['index']}", s["offset"], s["size"], s["addralign"], s["in_file"])
            for s in sections
            if s["type"] == _SHT_NOTE
        ]
        if not sections:
            containers = [
                (f"segment:{s['index']}", s["offset"], s["filesz"], s["align"], s["in_file"])
                for s in segments
                if s["type"] == _PT_NOTE
            ]
        notes: list[dict[str, Any]] = []
        for where, offset, size, align, in_file in containers:
            if not in_file:
                continue
            step = 8 if align == 8 else 4
            position, end = offset, offset + size
            while position + 12 <= end:
                if len(notes) >= MAX_NOTES:
                    self.issue("note_listing_capped", where)
                    return notes
                raw = self.unpack("III", position)
                if raw is None:  # pragma: no cover - guarded by in_file
                    break
                namesz, descsz, note_type = raw
                name_start = position + 12
                name_end = name_start + namesz
                desc_start = offset + _align(name_end - offset, step)
                desc_end = desc_start + descsz
                if name_end > end or desc_end > end:
                    self.issue("note_malformed", where)
                    break
                owner_raw = self.data[name_start:name_end].split(b"\x00", 1)[0]
                owner = decode_name(
                    owner_raw[:MAX_NOTE_OWNER_BYTES], len(owner_raw) > MAX_NOTE_OWNER_BYTES
                )
                desc = self.data[desc_start:desc_end]
                note: dict[str, Any] = {
                    "container": where,
                    "owner": owner.get("name"),
                    "type": note_type,
                    "desc_size": descsz,
                    "desc_hex": desc[:MAX_NOTE_DESC_BYTES].hex(),
                    "desc_truncated": descsz > MAX_NOTE_DESC_BYTES,
                }
                if "name_hex" in owner:
                    note["owner_hex"] = owner["name_hex"]
                if owner.get("name") == "FreeBSD" and note_type == 1 and descsz == 4:
                    note["freebsd_abi_tag"] = struct.unpack(self.endian + "I", desc)[0]
                elif owner.get("name") == "GNU" and note_type == 1 and descsz == 16:
                    os_id, major, minor, patch = struct.unpack(self.endian + "IIII", desc)
                    note["gnu_abi_tag"] = {
                        "os": os_id,
                        "os_name": _GNU_ABI_OS.get(os_id),
                        "kernel_version": f"{major}.{minor}.{patch}",
                    }
                elif owner.get("name") == "GNU" and note_type == 3:
                    note["build_id"] = desc.hex()
                notes.append(note)
                position = offset + _align(desc_end - offset, step)
        return notes

    def _comment(self, sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for section in sections:
            name = section["name"].get("name")
            if name != ".comment" or not section["in_file"]:
                continue
            raw = self.data[section["offset"] : section["offset"] + section["size"]]
            parts = [part for part in raw.split(b"\x00") if part]
            if len(parts) > MAX_COMMENT_STRINGS:
                self.issue("comment_listing_capped", f"section:{section['index']}")
            return [
                decode_name(part[:MAX_COMMENT_BYTES], len(part) > MAX_COMMENT_BYTES)
                for part in parts[:MAX_COMMENT_STRINGS]
            ]
        return []


def _align(value: int, step: int) -> int:
    return (value + step - 1) & ~(step - 1)


def decode_name(raw: bytes, truncated: bool = False) -> dict[str, Any]:
    """Strict UTF-8 name, or a hex rendering when the bytes are not UTF-8."""
    result: dict[str, Any]
    try:
        result = {"name": raw.decode("utf-8")}
    except UnicodeDecodeError:
        result = {"name": None, "name_hex": raw.hex()}
    if truncated:
        result["name_truncated"] = True
    return result


def decode_value(raw: bytes, truncated: bool = False) -> dict[str, Any]:
    """Strict UTF-8 value, or a hex rendering when the bytes are not UTF-8."""
    result: dict[str, Any]
    try:
        result = {"value": raw.decode("utf-8")}
    except UnicodeDecodeError:
        result = {"value": None, "value_hex": raw.hex()}
    if truncated:
        result["value_truncated"] = True
    return result


def parse_elf(data: bytes) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Parse one bounded ELF image into JSON-ready fields and parse issues.

    Raises :class:`ElfFormatError` only when the header itself is unusable.
    """
    parser = _Elf(data)
    fields = parser.parse()
    return fields, parser.issues
