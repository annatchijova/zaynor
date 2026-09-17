"""Contracts for bounded investigation, without epistemic authority.

This module deliberately stops before orchestration. It defines the typed
boundary between sealed ZAYNOR facts, an agent's investigative question, and
an observation returned by a tool. No object here can represent or mutate an
authoritative verdict, finding, hypothesis, score, or seal.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping

from zaynor.authority_seal import AuthoritySeal, verify_authoritative_result
from zaynor.schemas import EvidenceRef, ZaynorAuthoritativeResult

from .contracts import CapabilityEffect

_MAX_TEXT = 4_096
_MAX_ARGUMENT_BYTES = 64 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class InvestigationContractError(ValueError):
    """An investigation message violates its typed boundary."""


class EpistemicAuthority(StrEnum):
    AUTHORIZED = "AUTHORIZED"
    UNTRUSTED = "UNTRUSTED"


class InstructionAuthority(StrEnum):
    NONE = "NONE"


class InvestigationStatus(StrEnum):
    OPEN = "OPEN"
    BLOCKED = "BLOCKED"
    COMPLETE = "COMPLETE"


class ObservationStatus(StrEnum):
    OBSERVED = "OBSERVED"
    REJECTED = "REJECTED"
    ERROR = "ERROR"


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT:
        raise InvestigationContractError(f"{field} must be a non-empty string of at most {_MAX_TEXT} characters")
    return value


def _sha256(value: str, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise InvestigationContractError(f"{field} must be a lowercase SHA-256 hex digest")
    return value


def _reject_float(value: Any) -> None:
    if isinstance(value, float):
        raise InvestigationContractError("floats are not allowed in investigation contract payloads")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise InvestigationContractError("investigation payload mapping keys must be strings")
            _reject_float(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_float(item)


def _freeze_json(value: Any) -> Any:
    """Recursively detach and freeze JSON-shaped contract data."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    """Return an ordinary JSON-shaped copy for transport."""
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _canonical_json(value: Any, field: str) -> bytes:
    _reject_float(value)
    try:
        encoded = json.dumps(_thaw_json(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise InvestigationContractError(f"{field} must be JSON-compatible") from exc
    if len(encoded) > _MAX_ARGUMENT_BYTES:
        raise InvestigationContractError(f"{field} exceeds {_MAX_ARGUMENT_BYTES} bytes")
    return encoded


@dataclass(frozen=True)
class AuthorizedFacts:
    """A projection of sealed facts: authorized as evidence, never as instructions."""

    case_id: str
    result_sha256: str
    verdict: str
    finding_ids: tuple[str, ...]
    unknowns: tuple[str, ...]
    fracture_ids: tuple[str, ...]
    hypothesis_ids: tuple[str, ...]
    evidence_refs: tuple[EvidenceRef, ...]
    epistemic_authority: EpistemicAuthority = EpistemicAuthority.AUTHORIZED
    instruction_authority: InstructionAuthority = InstructionAuthority.NONE

    def __post_init__(self) -> None:
        _text(self.case_id, "case_id")
        _sha256(self.result_sha256, "result_sha256")
        _text(self.verdict, "verdict")
        if self.epistemic_authority is not EpistemicAuthority.AUTHORIZED:
            raise InvestigationContractError("authorized facts must remain AUTHORIZED")
        if self.instruction_authority is not InstructionAuthority.NONE:
            raise InvestigationContractError("authorized facts never carry instruction authority")

    @classmethod
    def from_sealed_result(cls, result: ZaynorAuthoritativeResult, seal: AuthoritySeal) -> "AuthorizedFacts":
        verify_authoritative_result(result, seal)
        return cls(
            case_id=result.case_id,
            result_sha256=seal.sha256,
            verdict=result.verdict,
            finding_ids=tuple(finding.finding_id for finding in result.findings),
            unknowns=result.unknowns,
            fracture_ids=tuple(str(item["id"]) for item in result.fractures if isinstance(item.get("id"), str)),
            hypothesis_ids=tuple(str(item["id"]) for item in result.hypotheses if isinstance(item.get("id"), str)),
            evidence_refs=tuple(ref for finding in result.findings for ref in finding.evidence_refs),
        )


@dataclass(frozen=True)
class InvestigationProposal:
    """A question/request proposed by the agent, not an authoritative state change."""

    proposal_id: str
    case_id: str
    question: str
    rationale: str
    requested_tool: str
    arguments: Mapping[str, Any]
    information_sought: str

    def __post_init__(self) -> None:
        _text(self.proposal_id, "proposal_id")
        _text(self.case_id, "case_id")
        _text(self.question, "question")
        _text(self.rationale, "rationale")
        _text(self.requested_tool, "requested_tool")
        _text(self.information_sought, "information_sought")
        if not isinstance(self.arguments, Mapping):
            raise InvestigationContractError("arguments must be an object")
        object.__setattr__(self, "arguments", _freeze_json(dict(self.arguments)))
        _canonical_json(self.arguments, "arguments")

    @property
    def arguments_digest(self) -> str:
        return hashlib.sha256(_canonical_json(dict(self.arguments), "arguments")).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        """Return a transport-only projection; this does not grant authority."""
        return {
            "proposal_id": self.proposal_id,
            "case_id": self.case_id,
            "question": self.question,
            "rationale": self.rationale,
            "requested_tool": self.requested_tool,
            "arguments": _thaw_json(self.arguments),
            "information_sought": self.information_sought,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "InvestigationProposal":
        """Strictly restore one proposal from its transport projection."""
        if not isinstance(raw, Mapping) or set(raw) != {
            "proposal_id", "case_id", "question", "rationale", "requested_tool",
            "arguments", "information_sought",
        }:
            raise InvestigationContractError("proposal projection has an invalid shape")
        try:
            return cls(**dict(raw))
        except (TypeError, InvestigationContractError) as exc:
            raise InvestigationContractError(f"invalid proposal projection: {exc}") from exc


@dataclass(frozen=True)
class ObservationEnvelope:
    """A tool result: metadata is typed; payload is always untrusted data."""

    observation_id: str
    case_id: str
    proposal_id: str
    tool_name: str
    capability_effect: CapabilityEffect
    resource: str
    arguments_digest: str
    provider: str
    payload: Any
    truncated: bool
    status: ObservationStatus
    payload_sha256: str
    epistemic_authority: EpistemicAuthority = EpistemicAuthority.UNTRUSTED
    instruction_authority: InstructionAuthority = InstructionAuthority.NONE

    def __post_init__(self) -> None:
        for value, field in (
            (self.observation_id, "observation_id"),
            (self.case_id, "case_id"),
            (self.proposal_id, "proposal_id"),
            (self.tool_name, "tool_name"),
            (self.resource, "resource"),
            (self.provider, "provider"),
        ):
            _text(value, field)
        _sha256(self.arguments_digest, "arguments_digest")
        _sha256(self.payload_sha256, "payload_sha256")
        if not isinstance(self.truncated, bool):
            raise InvestigationContractError("truncated must be boolean")
        if self.epistemic_authority is not EpistemicAuthority.UNTRUSTED:
            raise InvestigationContractError("tool observations are always UNTRUSTED")
        if self.instruction_authority is not InstructionAuthority.NONE:
            raise InvestigationContractError("tool observations never carry instruction authority")
        object.__setattr__(self, "payload", _freeze_json(self.payload))
        expected = hashlib.sha256(_canonical_json(self.payload, "payload")).hexdigest()
        if expected != self.payload_sha256:
            raise InvestigationContractError("payload_sha256 does not match payload")

    @classmethod
    def from_payload(
        cls,
        *,
        observation_id: str,
        case_id: str,
        proposal: InvestigationProposal,
        capability_effect: CapabilityEffect,
        resource: str,
        provider: str,
        payload: Any,
        truncated: bool = False,
        status: ObservationStatus = ObservationStatus.OBSERVED,
    ) -> "ObservationEnvelope":
        payload_sha256 = hashlib.sha256(_canonical_json(payload, "payload")).hexdigest()
        return cls(
            observation_id=observation_id,
            case_id=case_id,
            proposal_id=proposal.proposal_id,
            tool_name=proposal.requested_tool,
            capability_effect=capability_effect,
            resource=resource,
            arguments_digest=proposal.arguments_digest,
            provider=provider,
            payload=payload,
            truncated=truncated,
            status=status,
            payload_sha256=payload_sha256,
        )

    def as_dict(self) -> dict[str, Any]:
        """Return metadata plus untrusted payload for transport."""
        return {
            "observation_id": self.observation_id,
            "case_id": self.case_id,
            "proposal_id": self.proposal_id,
            "tool_name": self.tool_name,
            "capability_effect": self.capability_effect.value,
            "resource": self.resource,
            "arguments_digest": self.arguments_digest,
            "provider": self.provider,
            "payload": _thaw_json(self.payload),
            "truncated": self.truncated,
            "status": self.status.value,
            "payload_sha256": self.payload_sha256,
            "epistemic_authority": self.epistemic_authority.value,
            "instruction_authority": self.instruction_authority.value,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ObservationEnvelope":
        """Strictly restore one observation and reverify its payload hash."""
        fields = {
            "observation_id", "case_id", "proposal_id", "tool_name", "capability_effect",
            "resource", "arguments_digest", "provider", "payload", "truncated", "status",
            "payload_sha256", "epistemic_authority", "instruction_authority",
        }
        if not isinstance(raw, Mapping) or set(raw) != fields:
            raise InvestigationContractError("observation projection has an invalid shape")
        try:
            values = dict(raw)
            values["capability_effect"] = CapabilityEffect(values["capability_effect"])
            values["status"] = ObservationStatus(values["status"])
            values["epistemic_authority"] = EpistemicAuthority(values["epistemic_authority"])
            values["instruction_authority"] = InstructionAuthority(values["instruction_authority"])
            return cls(**values)
        except (KeyError, TypeError, ValueError, InvestigationContractError) as exc:
            raise InvestigationContractError(f"invalid observation projection: {exc}") from exc


@dataclass(frozen=True)
class InvestigationSession:
    """Immutable investigation ledger anchored to one sealed result version."""

    session_id: str
    case_id: str
    base_result_sha256: str
    proposals: tuple[InvestigationProposal, ...] = ()
    observations: tuple[ObservationEnvelope, ...] = ()
    status: InvestigationStatus = InvestigationStatus.OPEN

    def __post_init__(self) -> None:
        _text(self.session_id, "session_id")
        _text(self.case_id, "case_id")
        _sha256(self.base_result_sha256, "base_result_sha256")
        if len({proposal.proposal_id for proposal in self.proposals}) != len(self.proposals):
            raise InvestigationContractError("session contains duplicate proposal_id")
        proposal_ids = {proposal.proposal_id for proposal in self.proposals}
        if any(proposal.case_id != self.case_id for proposal in self.proposals):
            raise InvestigationContractError("proposal case_id does not match session")
        if len({observation.observation_id for observation in self.observations}) != len(self.observations):
            raise InvestigationContractError("session contains duplicate observation_id")
        for observation in self.observations:
            if observation.case_id != self.case_id or observation.proposal_id not in proposal_ids:
                raise InvestigationContractError("observation is not bound to this session and a known proposal")

    def add_proposal(self, proposal: InvestigationProposal) -> "InvestigationSession":
        if proposal.case_id != self.case_id:
            raise InvestigationContractError("proposal case_id does not match session")
        if any(item.proposal_id == proposal.proposal_id for item in self.proposals):
            raise InvestigationContractError("proposal_id already exists in session")
        return replace(self, proposals=(*self.proposals, proposal))

    def record_observation(self, observation: ObservationEnvelope) -> "InvestigationSession":
        if observation.case_id != self.case_id:
            raise InvestigationContractError("observation case_id does not match session")
        if observation.proposal_id not in {proposal.proposal_id for proposal in self.proposals}:
            raise InvestigationContractError("observation must reference a session proposal")
        if any(item.observation_id == observation.observation_id for item in self.observations):
            raise InvestigationContractError("observation_id already exists in session")
        return replace(self, observations=(*self.observations, observation))

    def as_dict(self) -> dict[str, Any]:
        """Return a deterministic, non-authoritative session projection."""
        return {
            "session_id": self.session_id,
            "case_id": self.case_id,
            "base_result_sha256": self.base_result_sha256,
            "proposals": [proposal.as_dict() for proposal in self.proposals],
            "observations": [observation.as_dict() for observation in self.observations],
            "status": self.status.value,
        }

    @property
    def snapshot_sha256(self) -> str:
        """Digest the session ledger without pretending it is an authority seal."""
        return hashlib.sha256(_canonical_json(self.as_dict(), "session")).hexdigest()

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "InvestigationSession":
        """Restore a session and validate all case, reference, and hash links."""
        fields = {"session_id", "case_id", "base_result_sha256", "proposals", "observations", "status"}
        if not isinstance(raw, Mapping) or set(raw) != fields:
            raise InvestigationContractError("session projection has an invalid shape")
        try:
            proposals = tuple(InvestigationProposal.from_dict(item) for item in raw["proposals"])
            observations = tuple(ObservationEnvelope.from_dict(item) for item in raw["observations"])
            status = InvestigationStatus(raw["status"])
            return cls(
                session_id=raw["session_id"],
                case_id=raw["case_id"],
                base_result_sha256=raw["base_result_sha256"],
                proposals=proposals,
                observations=observations,
                status=status,
            )
        except (KeyError, TypeError, ValueError, InvestigationContractError) as exc:
            raise InvestigationContractError(f"invalid session projection: {exc}") from exc
