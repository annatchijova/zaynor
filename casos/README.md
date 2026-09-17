# Case corpus

Ten cases, all from VIGIA's own corpus (Apache 2.0, Anna Tchijova) — nothing
invented here, nothing translated to a different schema.

## Real (5)

Publicly documented, real-world incidents, from `vigia-repo/data/cases/`:

- `VIGIA-NITROBA-M57-001.json` — the Nitroba/M57 Patents network forensics
  case (DFRWS 2009 challenge pcap). Widely known in the DFIR community.
- `VIGIA-REAL-SONY-001.json` — Sony Pictures Entertainment, 2014.
- `VIGIA-REAL-TARGET-001.json` — Target Corporation retail breach, 2013.
- `VIGIA-REAL-COLONIAL-001.json` — Colonial Pipeline ransomware, 2021.
- `VIGIA-REAL-008.json` — Cridex/Feodo banking trojan memory forensics.

## Canonical (5)

From `vigia_cases_canonical_v2.json` (52-case corpus, version 2.4), VIGIA's
professionally-designed intentionality vectors — real Peirce chains,
temporal violations, and CAIE fractures already authored:

- `case_083_sacrificio_del_peon.json`
- `case_024_paracaidista_timestomping.json`
- `case_026_ventrilocuo_process_hollowing.json`
- `case_008_paranoia_perimetro.json`
- `case_093_deepfake_estilo.json`

Confirmed by running both formats through the real pipeline
(`freeze` → `analyze`): `VIGIA-NITROBA-M57-001` → `SUSPICION`,
`case_083_sacrificio_del_peon` → `MALICE` — both match their own
`expected_verdict`.

Samuel's original 9 synthetic fixtures are preserved, unmodified, in
`../casos-samuel/` — not deleted, not merged in here.
