"""ADR-0005 revisit trigger, as a test.

The binary importers emit one observation per binary and keep every
binary-derived signal out of VIGIA until a calibrated P2 adapter exists.
Both decisions rest on how the vendored engine classifies binary evidence
today. If VIGIA recalibrates these types, moves them to another band, or
changes their corroboration role, this test fails on purpose: ADR-0005's
P2 adapter invariants must be re-read against the new engine before any
adapter is written.
"""

import sys

from zaynor.vendored_engine import VENDORED_ENGINE_PATH

sys.path.insert(0, str(VENDORED_ENGINE_PATH))
from vigia.tools.caie import (  # noqa: E402
    EVIDENCE_PROFILES,
    classify_domain_subband,
    evidence_role,
)

BINARY_TYPES = ("binary", "elf_executable", "pe_executable", "malware_static_analysis")


def test_binary_types_are_d5_media_per_artifact_cost_evidence():
    # D5-media is exempt from tail decay and feeds the per-artifact-cost
    # corroboration branch: one artifact must mean one distinct binary.
    for evidence_type in BINARY_TYPES:
        assert classify_domain_subband(evidence_type) == ("content_artifact", "D5-media")
        assert evidence_role(evidence_type) == "device"


def test_binary_types_are_still_uncalibrated_legacy_profiles():
    # P2 requires calibration (ADR-0004); until VIGIA replaces the legacy
    # fallback, no binary observation may be scored.
    for evidence_type in BINARY_TYPES:
        profile = EVIDENCE_PROFILES[evidence_type]
        assert (profile.spoofability, profile.base_weight) == (0.50, 0.20)
        assert profile.description.startswith("Uncalibrated")


def test_correlated_fractures_precedent_is_d5_soft_contextual():
    # The precedent ADR-0005 cites for per-binary fractures (B-136): several
    # signals from one analyzed object are correlated, not independent acts.
    assert classify_domain_subband("linguistic_forensics") == ("content_artifact", "D5-soft")
    assert evidence_role("linguistic_forensics") == "contextual"
