"""Adapted Velociraptor collection integration for ZAYNOR's DFIR path.

Module paths mirror the ANNACONDA stack this was adapted from
(`tools/velociraptor/adapter.py`, `vql_templates.py`, `MockTransport`,
`RestTransport`), translated to ZAYNOR's contracts:

- Row normalization happens once, at the transport boundary, so a live
  collection and a captured/replayed collection normalize identically.
- Each evidence window is sealed with a canonical `window_hash` in
  byte-for-byte lockstep with `zaynor.hybrid_integrations.verify_annaconda_window`
  (same `_canonicalize` + SHA-256 derivation), so the existing case-freeze
  boundary accepts it without any reimplementation there.
- Manifests describe artifacts, content hashes, and provenance. Custody
  chains distinguish the builder (who produced the collection) from the
  custodian (who currently holds it).

Authority boundary: this module is an EVIDENCE COLLECTOR ONLY. It never
computes a score, never emits a verdict, and never labels a claim. Scoring
and verdicts belong exclusively to ZAYNOR's deterministic engine (VIGÍA)
behind the existing freeze/analyze pipeline.
"""
