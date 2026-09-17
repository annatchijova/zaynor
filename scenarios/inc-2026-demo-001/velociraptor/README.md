# INC-2026-DEMO-001 — Velociraptor DFIR collection

Fully local, synthetic DFIR lab for the Velociraptor → ZAYNOR path.
Nothing here touches a real endpoint and no evidence content is ever
executed or followed as an instruction.

## Files

| File | Purpose |
| --- | --- |
| `simulate_endpoint_activity.py` | Writes the synthetic client-side lab state under `/tmp/kilo/zaynor-lab/` (auth log, collection.zip with a back-dated mtime, operator note). |
| `collector-spec.yaml` | Velociraptor collector definition for the demo (built-in sources only, one local client). |
| `captured-collection.json` | Byte-stable capture of the demo hunt results, replayed by `MockTransport` for reproducible tests and offline demos. |

## Live path (real Velociraptor server + local client)

1. Start the server (Docker or the release binary):
   ```bash
   docker run --rm -d --name velociraptor -p 8889:8889 -p 8009:8009 \
     -e VELOX_USER=admin -VELOX_PASSWORD='...see README...' \
     -e VELOX_ROLE=administrator \
     -v zaynor-vr-data:/velociraptor wlambert/velociraptor:latest
   ```
2. Register the local host as a client (same container runs the client
   against its own server) and confirm it appears in the GUI
   (`http://localhost:8889`).
3. Run the demo VQL as a hunt or a client collector (the catalog lives in
   `tools/velociraptor/vql_templates.py`):
   - `windows-processes` — built-in `pslist()` inventory;
   - `sim-auth-events` — reads the synthetic auth log from the lab dir;
   - `sim-lab-files` — `glob()` over the lab evidence directory;
   - `sim-operator-note` — the operator follow-up note, as evidence.
4. Export the results (JSONL) — `scripts/demo_dfir.py --mode live` mints an
   API token from the server config and pulls the records via the adapted
   `RestTransport`.

## Offline replay (no server needed)

`scripts/demo_dfir.py --mode mock` replays `captured-collection.json`
through the exact same normalization and window-sealing path a live
collection takes. The demo verdict is therefore reproducible without any
collector running.

## Authority boundary

The Velociraptor side only COLLECTS. The adapted adapter normalizes rows
and seals an evidence window (`window_hash`, manifest, custody roles) and
never computes a score, a verdict, or a label. VIGÍA — behind
`zaynor analyze` on the frozen case — is the only component that decides
what the evidence supports.
