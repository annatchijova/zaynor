"""Non-authoritative security framework context.

These annotations explain an already-authoritative result.  They are not
evidence, do not establish causality, and cannot promote a finding state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .authority_seal import AuthoritySeal, seal_authoritative_result, verify_authoritative_result
from .schemas import ZaynorAuthoritativeResult


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
class OwaspAnnotation:
    """OWASP context for an already-authoritative result.

    This is a mapping or control note, never evidence and never a verdict
    transition. ``evidence_refs`` may explain the mapping but cannot promote
    the referenced finding.
    """

    version: str
    category: str
    mapping_status: str
    justification: str
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class FrameworkContext:
    mitre: tuple[MitreAnnotation, ...] = ()
    nist: tuple[NistAnnotation, ...] = ()
    owasp: tuple[OwaspAnnotation, ...] = ()


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


class ConsultPackageError(ValueError):
    """A consult package cannot be built from the given result/seal pair."""


def build_consult_package(
    result: ZaynorAuthoritativeResult, seal: AuthoritySeal, *, framework: FrameworkContext | None = None
) -> tuple[AuthoritativePackage, AuthoritySeal]:
    """Bridge `zaynor analyze`'s stored (result, seal) into a sealed
    `AuthoritativePackage`, the shape `ConsultTools` requires.

    `zaynor analyze` seals the bare `ZaynorAuthoritativeResult` directly,
    not a package -- these are two different sealed objects with different
    canonical bytes (see `agents/README.md`'s "architectural mismatch, not
    yet resolved" note). This function is the resolution: it verifies the
    ALREADY-SEALED result first -- a package can only be built over a
    result already proven authoritative, never a candidate that merely
    looks right -- then wraps and seals it as a package.

    `framework` defaults to empty. No MITRE/NIST/OWASP mapper exists yet:
    `Finding.mitre`/`Finding.nist` are passed through verbatim from
    whatever the engine emitted (`adapter.py:73-74`), and unpopulated by
    every case in the current corpus. An empty `FrameworkContext` is the
    honest starting point -- fabricating mapped annotations from data that
    is not actually produced anywhere would be exactly the kind of
    overclaim this project has repeatedly caught and reverted elsewhere.
    """
    if not isinstance(result, ZaynorAuthoritativeResult):
        raise ConsultPackageError("consult package must be built from a ZaynorAuthoritativeResult")
    try:
        verify_authoritative_result(result, seal)
    except (RuntimeError, ValueError) as exc:
        raise ConsultPackageError("result does not verify against its own seal") from exc
    package = AuthoritativePackage(result=result, framework=framework or FrameworkContext())
    package_seal = seal_authoritative_package(package)
    return package, package_seal
