"""Deterministic byte measurements for static binary triage.

Every value produced here is a pure function of the input bytes and is
computed without binary floating point, so a frozen observation can be
re-derived bit-for-bit on any platform from the frozen original.

Shannon entropy is irrational in general, so it cannot be an exact
rational. It is computed with :mod:`decimal`, whose ``ln`` is correctly
rounded (ROUND_HALF_EVEN) in software, then quantized and emitted as a
string together with the byte histogram it was derived from. ``math.log``
is deliberately avoided: libm results are platform-dependent at the ULP
level, which is the same reason VIGIA replaced it with precomputed
rational tables in its scorer.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from decimal import ROUND_HALF_EVEN, Context, Decimal
from functools import lru_cache
from typing import Any

ENTROPY_METHOD = "shannon-bits-per-byte/decimal-prec40-ln/quantize-1e-6-half-even"

_CONTEXT = Context(prec=40, rounding=ROUND_HALF_EVEN)
_QUANTUM = Decimal("0.000001")
_ZERO = Decimal(0)


def byte_histogram(data: bytes | memoryview) -> list[int]:
    """Count every byte value; index ``i`` holds the count of byte ``i``."""
    counts = Counter(data)
    return [counts.get(value, 0) for value in range(256)]


@lru_cache(maxsize=8192)
def _ln(value: int) -> Decimal:
    return _CONTEXT.ln(Decimal(value))


_LN2 = _CONTEXT.ln(Decimal(2))


def shannon_entropy(histogram: list[int]) -> str | None:
    """Entropy in bits per byte as a fixed-point string, or None when empty.

    H = log2(N) - (sum(c * ln c)) / (N * ln 2). An empty input has no
    entropy (None), which is different from an entropy of zero.
    """
    total = sum(histogram)
    if total == 0:
        return None
    weighted = _ZERO
    for count in histogram:
        if count:
            weighted = _CONTEXT.add(weighted, _CONTEXT.multiply(Decimal(count), _ln(count)))
    entropy = _CONTEXT.subtract(
        _CONTEXT.divide(_ln(total), _LN2),
        _CONTEXT.divide(weighted, _CONTEXT.multiply(Decimal(total), _LN2)),
    )
    if entropy < _ZERO:
        # Only reachable as a rounding residue of an exact zero.
        entropy = _ZERO
    quantized = entropy.quantize(_QUANTUM, rounding=ROUND_HALF_EVEN, context=_CONTEXT)
    if quantized.is_zero():
        quantized = quantized.copy_abs()
    return format(quantized, "f")


def sha256_hex(data: bytes | memoryview) -> str:
    return hashlib.sha256(data).hexdigest()


class MeasurementBudget:
    """Caps how many bytes one binary may hash and histogram.

    Section and segment ranges come from attacker-controlled headers and may
    overlap or repeat; without a budget a small file could demand gigabytes
    of hashing. Once exhausted, further ranges are reported as unmeasured.
    """

    def __init__(self, limit: int) -> None:
        self.remaining = limit
        self.exhausted = False

    def take(self, length: int) -> bool:
        if length > self.remaining:
            self.exhausted = True
            return False
        self.remaining -= length
        return True


STRING_MIN_CHARS = 6
MAX_STRINGS_LISTED = 1024
MAX_STRING_CHARS = 200
_ASCII_RUN = re.compile(rb"[\x20-\x7e]{%d,}" % STRING_MIN_CHARS)
_UTF16LE_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % STRING_MIN_CHARS)


def extract_strings(data: bytes) -> dict[str, Any]:
    """Printable ASCII and UTF-16LE runs, the `strings` step of static triage.

    Selection is purely positional — the first runs by file offset — so the
    listing never encodes a judgment about which strings matter. Totals count
    every run, and the frozen original keeps the rest.
    """
    found: list[tuple[int, str, int, str]] = []
    totals = {"ascii": 0, "utf-16le": 0}
    for match in _ASCII_RUN.finditer(data):
        totals["ascii"] += 1
        if totals["ascii"] <= MAX_STRINGS_LISTED:
            text = match.group().decode("ascii")
            found.append((match.start(), "ascii", len(text), text))
    for match in _UTF16LE_RUN.finditer(data):
        totals["utf-16le"] += 1
        if totals["utf-16le"] <= MAX_STRINGS_LISTED:
            text = match.group().decode("utf-16-le")
            found.append((match.start(), "utf-16le", len(text), text))
    found.sort(key=lambda item: (item[0], item[1]))
    listed = [
        {
            "offset": offset,
            "encoding": encoding,
            "length": length,
            "value": text[:MAX_STRING_CHARS],
            "value_truncated": length > MAX_STRING_CHARS,
        }
        for offset, encoding, length, text in found[:MAX_STRINGS_LISTED]
    ]
    return {
        "min_chars": STRING_MIN_CHARS,
        "total": totals["ascii"] + totals["utf-16le"],
        "totals_by_encoding": totals,
        "listed": listed,
        "listing_truncated": totals["ascii"] + totals["utf-16le"] > len(listed),
    }


def measure_range(data: memoryview, offset: int, size: int) -> dict[str, str | None]:
    """Hash and entropy of one in-bounds byte range."""
    view = data[offset : offset + size]
    return {
        "sha256": sha256_hex(view),
        "entropy_bits_per_byte": shannon_entropy(byte_histogram(view)),
    }
