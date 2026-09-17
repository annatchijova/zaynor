#!/usr/bin/env python3
"""Build a real EBS v1 bundle (bundle_hash/graph_hash/policy_hash/
decision_hash) from a VIGIA case-corpus JSON file, for independent
verification with `vendor/vigia_engine/forensics/verify_ebs_v1.py`.

This is a DIFFERENT bundle than `zaynor analyze`'s stored `bundle.json`:
that one is Mode 1's own CLI output (agent_verdict/pipeline_results/
audit_trail — what `zaynor audit` checks). This one is the EBS v1
standard bundle VIGIA's own `vigia/core/bundle_builder.py::build_bundle`
produces from the direct scorer path (`vigia_scorer.py::_vigia_score`) —
the shape `verify_ebs_v1.py` actually understands. Confirmed by reading
both: `zaynor analyze` never calls `build_bundle`, so there was nothing
for `verify_ebs_v1.py` to check without this script.

Usage:
    python3 scripts/build_ebs_bundle.py casos/case_083_sacrificio_del_peon.json bundle.ebs.json
    python3 vendor/vigia_engine/forensics/verify_ebs_v1.py bundle.ebs.json --verbose --strict

Works today for VIGIA's own case-corpus JSON schema (artifacts[] with
evidence_type/raw_score/prior_trust/provenance_chain, or the rich
case-JSON schema with content/metadata — both normalize via
`vigia_scorer._normalize_case`). It does not (yet) work for the
image-evidence route: that one only ever produces Mode 1's own bundle
shape, not this one — see GUIA_PERITOS.md for which verifier applies to
which evidence type.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_VENDORED_ENGINE = _REPO_ROOT / "vendor" / "vigia_engine"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("case_file", help="a VIGIA case-corpus JSON file (e.g. under casos/)")
    parser.add_argument("output_file", help="where to write the EBS v1 bundle")
    args = parser.parse_args(argv)

    if not _VENDORED_ENGINE.is_dir():
        print(f"vendored engine not found at {_VENDORED_ENGINE}", file=sys.stderr)
        return 2
    sys.path.insert(0, str(_VENDORED_ENGINE))

    from vigia.core.bundle_builder import build_bundle
    from vigia_scorer import _vigia_score

    case_path = Path(args.case_file)
    case = json.loads(case_path.read_text(encoding="utf-8"))
    score = _vigia_score(case)
    if score.get("verdict") == "ERROR":
        print(f"scoring failed: {score.get('error', 'unknown error')}", file=sys.stderr)
        return 1
    bundle = build_bundle(case, score)

    output_path = Path(args.output_file)
    output_path.write_text(json.dumps(bundle, indent=2, default=str, sort_keys=True), encoding="utf-8")
    print(f"verdict: {score.get('verdict')}")
    print(f"bundle written to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
