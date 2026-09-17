# Case corpus

This directory contains nine synthetic, authorized fixtures for ZAYNOR's
deterministic replay and post-incident investigation pipeline. Each fixture
records which replay rule declared the incident, then supplies the already
collected evidence that crosses the case-freeze boundary. Evidence acquisition
and autonomous response remain out of scope.

## Design

Each `INC-*.json` file contains:

- an incident declared by the synthetic replay pipeline;
- the deterministic declaration rule and evidence references that triggered it;
- a bounded evidence scope with explicit collection limitations;
- factual evidence records with stable references;
- a `lineage_id` that identifies records derived from the same source;
- untrusted narrative content as data with no instruction authority.

The fixture files intentionally contain no verdict, hypothesis status, ATT&CK
mapping, or expected conclusion. Declaration metadata explains why the freeze
occurred; it does not determine the forensic result. Evaluation values would
contaminate a blind analysis if they crossed the case-freeze boundary.

Evaluation truth lives outside this directory in
`../tests/fixtures/case-ground-truth.json`. It is test data only and must never
be included in a frozen evidence bundle or provided to the narrator before the
authoritative result is sealed.

`index.json` is a discovery catalog. `case.schema.json` describes the portable
fixture format.

The case freezer must select exactly one `INC-*.json` file. It must not freeze
this directory recursively, because the catalog, schema, and documentation are
not evidence.

## Corpus goals

The cases exercise distinct forensic failure modes:

1. a self-report that overlaps with pre-positioned persistence;
2. a protective social narrative that conflicts with host evidence;
3. executable private memory with both malicious and benign context;
4. Linux utility replacement and hidden scheduler entries;
5. incomplete acquisition that requires abstention;
6. a small anomalous sequence inside mostly normal traffic;
7. false consensus caused by shared provenance;
8. user-mode API hooks and recurring malware persistence;
9. credential-store collection on a domain controller.

The expected result is about the evidenced activity, not attribution. A
malicious activity verdict does not identify the person at the keyboard,
prove data exfiltration, or establish the initial access method unless those
facts are separately supported.

## Validation

Run:

```bash
python -m pytest tests/test_case_corpus.py
```

The test checks structural consistency, case/evaluation separation, reference
uniqueness, lineage presence, integer-only numeric data, and removal of legacy
engine branding.
