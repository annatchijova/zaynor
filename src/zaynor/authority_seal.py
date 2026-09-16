"""Deterministic, tamper-evident sealing for ZAYNOR authority results.

The seal covers only the authoritative result.  Recording time, operator
notes, and transport metadata belong outside this payload so that they cannot
make an otherwise identical decision unverifiable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, fields, is_dataclass
from fractions import Fraction
from typing import Any, Mapping


CANONICALIZE_VERSION = "zaynor-authority-v1"


class SealError(ValueError):
    """Raised when an authority result cannot be sealed or verified."""


def _typed(value: Any) -> dict[str, Any]:
    """Return one canonical, typed representation of *value*.

    Floats are deliberately rejected: an approximate number must not enter a
    digest that is presented as an authoritative decision.
    """

    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "bool", "value": value}
    if isinstance(value, int):
        return {"type": "int", "value": str(value)}
    if isinstance(value, Fraction):
        return {
            "type": "fraction",
            "numerator": str(value.numerator),
            "denominator": str(value.denominator),
        }
    if isinstance(value, float):
        raise SealError("float is not allowed in the authoritative payload")
    if isinstance(value, str):
        return {"type": "str", "value": value}
    if is_dataclass(value) and not isinstance(value, type):
        return {
            "type": "dataclass",
            "name": f"{type(value).__module__}.{type(value).__qualname__}",
            "fields": {
                field.name: _typed(getattr(value, field.name))
                for field in fields(value)
            },
        }
    if isinstance(value, Mapping):
        entries = [(_typed(key), _typed(item)) for key, item in value.items()]
        entries.sort(key=lambda pair: _json(pair[0]))
        return {"type": "mapping", "value": entries}
    if isinstance(value, tuple):
        return {"type": "tuple", "value": [_typed(item) for item in value]}
    if isinstance(value, list):
        return {"type": "list", "value": [_typed(item) for item in value]}
    raise SealError(f"unsupported authoritative value: {type(value).__name__}")


def _json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def canonical_bytes(result: Any) -> bytes:
    """Encode a result with the versioned canonical representation."""

    payload = {
        "canonicalize_version": CANONICALIZE_VERSION,
        "result": _typed(result),
    }
    return _json(payload)


@dataclass(frozen=True)
class AuthoritySeal:
    """Digest envelope; volatile metadata must remain outside this object."""

    canonicalize_version: str
    sha256: str


def seal_authoritative_result(result: Any) -> AuthoritySeal:
    """Seal *result* and return its reproducible SHA-256 digest."""

    digest = hashlib.sha256(canonical_bytes(result)).hexdigest()
    return AuthoritySeal(CANONICALIZE_VERSION, digest)


def verify_authoritative_result(result: Any, seal: AuthoritySeal) -> bool:
    """Recompute and verify a seal without trusting producer-side state."""

    if seal.canonicalize_version != CANONICALIZE_VERSION:
        raise SealError("unsupported canonicalization version")
    expected = seal_authoritative_result(result).sha256
    if not isinstance(seal.sha256, str) or len(seal.sha256) != 64:
        raise SealError("invalid SHA-256 seal")
    if not hmac.compare_digest(expected, seal.sha256):
        raise SealError("authoritative result seal mismatch")
    return True
