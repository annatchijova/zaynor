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
from collections import Counter
from decimal import ROUND_HALF_EVEN, Context, Decimal
from functools import lru_cache

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


def measure_range(data: memoryview, offset: int, size: int) -> dict[str, str | None]:
    """Hash and entropy of one in-bounds byte range."""
    view = data[offset : offset + size]
    return {
        "sha256": sha256_hex(view),
        "entropy_bits_per_byte": shannon_entropy(byte_histogram(view)),
    }
