"""Non-authoritative MITRE ATT&CK and NIST context.

These annotations explain an already-authoritative result.  They are not
evidence, do not establish causality, and cannot promote a finding state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .authority_seal import AuthoritySeal, seal_authoritative_result, verify_authoritative_result


@dataclass(frozen=True)
class MitreAnnotation:
    technique: str
    mapping_status: str
    justification: str


@dataclass(frozen=True)
class NistAnnotation:
    function: str
    category: str
    mapping_status: str
    justification: str


@dataclass(frozen=True)
class FrameworkContext:
    mitre: tuple[MitreAnnotation, ...] = ()
    nist: tuple[NistAnnotation, ...] = ()


@dataclass(frozen=True)
class AuthoritativePackage:
    """The result and its explanatory framework context, sealed together."""

    result: Any
    framework: FrameworkContext = FrameworkContext()


def seal_authoritative_package(package: AuthoritativePackage) -> AuthoritySeal:
    """Seal forensic authority and framework context as one package."""

    return seal_authoritative_result(package)


def verify_authoritative_package(package: AuthoritativePackage, seal: AuthoritySeal) -> bool:
    """Verify the complete package, including annotations."""

    return verify_authoritative_result(package, seal)
