"""Adapted Velociraptor evidence-window adapter (ANNACONDA lineage).

Adapted from the ANNACONDA/Velociraptor stack's `tools/velociraptor/adapter.py`
pattern: a transport fetches raw query results, the adapter normalizes rows,
seals an evidence window with a canonical `window_hash`, and writes a
collection manifest plus a chain-of-custody log that distinguishes the
builder from the custodian.

What was kept from the original pattern:
- `MockTransport` / `RestTransport` transport split (replay vs live REST).
- One normalization seam for all rows, with stable column names and types.
- `window_hash` computed with the same canonical-JSON SHA-256 derivation as
  ANNACONDA's `_sha256_canonical()`, in lockstep with
  `zaynor.hybrid_integrations.verify_annaconda_window()` so ZAYNOR's
  existing case-freeze boundary verifies the window unchanged.
- Manifest + custody semantics (builder vs custodian).

What was changed for ZAYNOR:
- No scoring, no CAIE taxonomy, no verdict vocabulary anywhere: this
  module is an evidence collector only.
- Custody records fold into ZAYNOR's own custody.json at freeze time; the
  collection-side custody log here is provenance input, not a second
  audit authority.
"""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from vendor.vigia_engine.vigia.core.canonicalize import _canonicalize

from tools.velociraptor import vql_templates

V1_SCHEMA_VERSION = 1


class VelociraptorAdapterError(ValueError):
    """A collection, transport, or window input is invalid or failed closed."""


def _canonical_hash(value: Any) -> bytes:
    # Byte-for-byte lockstep with ANNACONDA's _sha256_canonical() and
    # zaynor.hybrid_integrations._canonical_hash().
    return json.dumps(_canonicalize(value), sort_keys=True, ensure_ascii=True).encode()


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def window_hash(window: dict[str, Any]) -> str:
    """Seal a window body with its canonical SHA-256 `window_hash`.

    The hash covers every key except `window_hash` itself, over the
    canonicalized JSON form — the exact derivation
    `zaynor.hybrid_integrations.verify_annaconda_window()` re-verifies.
    """
    body = {key: value for key, value in window.items() if key != "window_hash"}
    return hashlib.sha256(_canonical_hash(body)).hexdigest()


def _seal_window(window: dict[str, Any]) -> dict[str, Any]:
    sealed = dict(window)
    sealed["window_hash"] = window_hash(sealed)
    return sealed


def normalize_timestamp(value: Any) -> str | None:
    """Normalize a timestamp to ISO-8601 UTC, or None when unparseable.

    Velociraptor returns time values as epoch nanoseconds (int/float),
    ISO strings, or Velociraptor's own {value}{unit} encodings depending
    on source. One normalizer keeps every downstream consumer type-stable.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        # Velociraptor epoch times are microseconds since the epoch.
        seconds = value / 1_000_000.0 if value > 10**11 else float(value)
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    if isinstance(value, dict):
        nested = value.get("value")
        if nested is not None:
            return normalize_timestamp(nested)
        return None
    return None


def _normalize_value(value: Any) -> Any:
    """Coerce one cell to a stable JSON type (str, int, float, bool, None)."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        ts = normalize_timestamp(value)
        if ts is not None:
            return ts
        return {str(k): _normalize_value(v) for k, v in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return [_normalize_value(item) for item in value]
    return str(value)


class MockTransport:
    """Replay a captured collection from a JSON file or in-memory rows.

    The capture format is exactly what `RestTransport` produces when
    `VelociraptorAdapter.collect` runs live, so replay and live paths
    normalize identically:

        [{"artifact_id": str, "columns": [...], "rows": [[...], ...]}, ...]
    """

    def __init__(self, capture: list[dict[str, Any]] | str | Path):
        if isinstance(capture, (str, Path)):
            capture = json.loads(Path(capture).read_text(encoding="utf-8"))
        if not isinstance(capture, list):
            raise VelociraptorAdapterError("mock capture must be a list")
        self._capture = capture

    def query(self, vql: str) -> Iterator[dict[str, Any]]:  # pragma: no cover - simple
        yield from self._rows_for_vql(vql)

    def _rows_for_vql(self, vql: str) -> Iterator[dict[str, Any]]:
        # MockTransport replays pre-captured results; it never interprets VQL.
        for entry in self._capture:
            for row in entry.get("rows", []):
                yield row
        return

    def rows_for_artifact(self, artifact_id: str) -> Iterator[dict[str, Any]]:
        for entry in self._capture:
            if entry.get("artifact_id") != artifact_id:
                continue
            columns = entry.get("columns", [])
            for values in entry.get("rows", []):
                if not isinstance(values, list) or len(values) != len(columns):
                    raise VelociraptorAdapterError(
                        f"capture row/column mismatch for artifact {artifact_id!r}"
                    )
                yield dict(zip(columns, values, strict=True))


class RestTransport:
    """Query a live Velociraptor server through its GUI API proxy.

    Sends read-only VQL to ``POST /api/v1/query`` with HTTP basic auth --
    the same scripting surface Velociraptor documents for external
    automation. A ``ssl_context`` may be passed for the lab's self-signed
    certificate; ``None`` uses the default trust store. Requests are
    bounded: one POST per query, response capped by ``max_response_bytes``.
    No shell, no filesystem writes, no arbitrary network: the only
    capability is running the VQL the caller passes in.
    """

    def __init__(
        self,
        base_url: str,
        username: str | None = None,
        password: str | None = None,
        *,
        ssl_context: Any = None,
        timeout_seconds: int = 120,
        max_response_bytes: int = 16 * 1024 * 1024,
    ):
        self._base_url = base_url.rstrip("/")
        self._basic_token = None
        if username is not None and password is not None:
            raw = f"{username}:{password}".encode("utf-8")
            self._basic_token = base64.b64encode(raw).decode("ascii")
        self._ssl_context = ssl_context
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes

    def query(self, vql: str) -> Iterator[dict[str, Any]]:
        request = urllib.request.Request(
            f"{self._base_url}/api/v1/query",
            data=json.dumps({"query": vql}).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self._timeout_seconds, context=self._ssl_context
            ) as response:
                payload = response.read(self._max_response_bytes + 1)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise VelociraptorAdapterError(f"velociraptor REST query failed: {exc}") from exc
        if len(payload) > self._max_response_bytes:
            raise VelociraptorAdapterError("velociraptor REST response exceeded size bound")
        for line in payload.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise VelociraptorAdapterError(f"unparseable API record: {exc}") from exc
            if isinstance(record, dict):
                yield record

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._basic_token is not None:
            headers["Authorization"] = f"Basic {self._basic_token}"
        return headers


@dataclass
class CollectionManifest:
    """Collection-side manifest: what was collected, from where, by whom."""

    collection_id: str
    built_at: str
    builder: str
    transport: str
    artifacts: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "collection_id": self.collection_id,
            "built_at": self.built_at,
            "builder": self.builder,
            "transport": self.transport,
            "artifact_count": len(self.artifacts),
            "artifacts": self.artifacts,
        }


class ChainOfCustody:
    """Collection-side custody chain: builder vs custodian records.

    The builder produces the collection; the custodian takes custody of
    it afterwards (e.g. the ZAYNOR staging step). This log is provenance
    input for ZAYNOR's case freezer — it makes no legal custody claim.
    """

    def __init__(self, collection_id: str):
        self.collection_id = collection_id
        self.records: list[dict[str, Any]] = []

    def add(
        self,
        operation: str,
        actor: str,
        role: str,
        artifact_hash: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.records.append(
            {
                "operation": operation,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "actor": actor,
                "role": role,
                "artifact_hash": artifact_hash,
                "metadata": metadata or {},
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "collection_id": self.collection_id,
            "n_records": len(self.records),
            "records": self.records,
        }


class VelociraptorAdapter:
    """Collect, normalize, and seal Velociraptor query results.

    One `collect()` call produces an immutable, hash-verifiable evidence
    window for a single synthetic incident case:

        {
          "schema_version": 1,
          "window_id": "CASE-w000001",
          "case_id": "INC-...",
          "collected_at": ISO-8601,
          "transport": "mock" | "rest",
          "custody": {"builder": str, "collected_at": ISO-8601},
          "artifacts": [ { "artifact_id": str,
                           "evidence_type": str,
                           "row_count": int,
                           "rows": [normalized row objects] },
                        ... ],
          "window_hash": "<sha256 of canonical JSON of everything above>"
        }

    Normalization (the seam ANNACONDA owned, kept identical here):
    - rows become objects with stable column names;
    - timestamps become ISO-8601 UTC strings;
    - every cell coerces to a stable JSON type;
    - each row is stamped with its artifact's `lineage_id` (the artifact_id)
      so downstream provenance/independence checks stay anchored to the
      collection lineage, not to per-row invention.
    """

    def __init__(self, *, builder: str = "zaynor-dfir-demo", source: str = "velociraptor"):
        self._builder = builder
        self._source = source

    def collect(
        self,
        case_id: str,
        artifacts: list[tuple[str, Iterator[dict[str, Any]]]],
        *,
        transport: str = "mock",
        window_index: int = 1,
    ) -> dict[str, Any]:
        """Build one sealed window from artifact/row-iterator pairs.

        `artifacts` entries are (artifact_id, row-iterator) pairs; rows must
        be flat dictionaries with string keys.
        """
        if not isinstance(case_id, str) or not case_id:
            raise VelociraptorAdapterError("case_id must be a non-empty string")
        collected_at = datetime.now(timezone.utc).isoformat()
        window_id = f"{case_id}-w{window_index:06d}"

        normalized_artifacts: list[dict[str, Any]] = []
        for artifact_id, rows in artifacts:
            normalized_artifacts.append(self._normalize_artifact(artifact_id, rows))

        window = {
            "schema_version": V1_SCHEMA_VERSION,
            "window_id": window_id,
            "case_id": case_id,
            "collected_at": collected_at,
            "transport": transport,
            "source": self._source,
            "custody": {
                # Same envelope shape as the AIOps path (see
                # tools/aiops/aggregator/app.py stage_incident_bundle):
                # window["custody"]["builder"] is THE custody builder field.
                "builder": self._builder,
                "collected_at": collected_at,
            },
            "artifacts": normalized_artifacts,
        }
        return _seal_window(window)

    def _normalize_artifact(self, artifact_id: str, rows: Iterator[dict[str, Any]]) -> dict[str, Any]:
        spec = vql_templates.CATALOG_BY_ID.get(artifact_id)
        if spec is None:
            raise VelociraptorAdapterError(f"unknown artifact_id: {artifact_id!r}")
        normalized_rows: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict) or any(not isinstance(key, str) for key in row):
                raise VelociraptorAdapterError(
                    f"artifact {artifact_id!r} row is not an object with string keys"
                )
            normalized_rows.append(
                {key: _normalize_value(value) for key, value in sorted(row.items())}
            )
        return {
            "artifact_id": artifact_id,
            "evidence_type": spec.evidence_type,
            "row_count": len(normalized_rows),
            "lineage_id": artifact_id,
            "rows": normalized_rows,
        }


def export_collection(
    window: dict[str, Any],
    output_root: Path,
    *,
    builder: str = "velociraptor-demo-collector",
    custodian: str = "zaynor-dfir-staging",
) -> tuple[Path, dict[str, Any]]:
    """Write a sealed window plus its collection manifest and custody chain
    to `output_root` (created if missing).

    Layout (deterministic, what ZAYNOR's staging + freezer consume):

        <output_root>/
            window.json          # the sealed evidence window
            collection-manifest.json
            custody.json

    Returns (output_root, window). Raises on any tampering with the window
    hash before a single byte is written — fail closed, write nothing.
    """
    from zaynor.hybrid_integrations import verify_annaconda_window

    verify_annaconda_window(window)
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=True)

    collection_id = f"{window['case_id']}-collection"
    manifest = CollectionManifest(
        collection_id=collection_id,
        built_at=window.get("collected_at", datetime.now(timezone.utc).isoformat()),
        builder=builder,
        transport=window.get("transport", "mock"),
    )
    custody = ChainOfCustody(collection_id=collection_id)

    (root / "window.json").write_bytes(_json_bytes(window) + b"\n")
    for artifact in window["artifacts"]:
        artifact_hash = hashlib.sha256(
            json.dumps(artifact, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()
        manifest.artifacts.append(
            {
                "artifact_id": artifact["artifact_id"],
                "evidence_type": artifact["evidence_type"],
                "row_count": artifact["row_count"],
                "lineage_id": artifact["lineage_id"],
                "sha256": artifact_hash,
            }
        )
        custody.add(
            "BUILD_ARTIFACT",
            actor=builder,
            role="builder",
            artifact_hash=artifact_hash,
            metadata={"artifact_id": artifact["artifact_id"]},
        )

    custody.add("TRANSFER_CUSTODY", actor=custodian, role="custodian", metadata={
        "window_id": window.get("window_id", ""),
        "window_hash": window["window_hash"],
    })
    if not custody.records:
        raise VelociraptorAdapterError("custody chain is empty")
    (root / "collection-manifest.json").write_bytes(_json_bytes(manifest.to_dict()) + b"\n")
    (root / "custody.json").write_text(json.dumps(custody.to_dict(), sort_keys=True, indent=2), encoding="utf-8")
    return root, window
