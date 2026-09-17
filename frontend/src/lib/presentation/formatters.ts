import type { AuthoritativeResult, Confidence, EvidenceRef } from "@/lib/api/contracts";

const ENGINE_DISPLAY_NAME = "ZAYNOR deterministic engine (Mode 1)";

/**
 * A case-facing screen names ZAYNOR, not its vendored internals.
 *
 * `result.engine.name` is real, correct provenance metadata for an audit
 * trail (the backend's actual engine identifier), but this function's
 * output is what an analyst reads on the case
 * screens. Mirrors the same fix already applied on the report-rendering
 * side (`src/zaynor/report.py::_engine_display`) -- ZAYNOR is its own
 * product, the vendored engine's raw name does not belong in the UI.
 */
export function formatEngineDisplay(engine: AuthoritativeResult["engine"]): string {
  return engine.version ? `${ENGINE_DISPLAY_NAME} ${engine.version}` : ENGINE_DISPLAY_NAME;
}

const confidenceLabels: Record<Confidence, string> = {
  HIGH: "Alta",
  LOW: "Baja",
  MEDIUM: "Media",
  UNKNOWN: "No declarada",
};

export function formatConfidence(confidence: Confidence): string {
  return confidenceLabels[confidence];
}

export function formatDateTime(value: string | null, locale = "es-AR"): string {
  if (!value) {
    return "No registrado";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "Fecha no válida";
  }

  return new Intl.DateTimeFormat(locale, {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(date);
}

export function formatHash(hash: string, prefixLength = 12, suffixLength = 8): string {
  if (!hash) {
    return "No disponible";
  }

  if (hash.length <= prefixLength + suffixLength) {
    return hash;
  }

  return `${hash.slice(0, prefixLength)}…${hash.slice(-suffixLength)}`;
}

export function formatEvidenceRefs(references: readonly EvidenceRef[]): string {
  if (!references.length) {
    return "Sin referencias de evidencia";
  }

  return references.map(({ artifact }) => artifact).join(", ");
}

export function formatFileSize(sizeBytes: number, locale = "es-AR"): string {
  if (sizeBytes < 1024) {
    return `${new Intl.NumberFormat(locale).format(sizeBytes)} B`;
  }

  const units = ["KiB", "MiB", "GiB"];
  const exponent = Math.min(Math.floor(Math.log(sizeBytes) / Math.log(1024)), units.length);
  const value = sizeBytes / 1024 ** exponent;

  return `${new Intl.NumberFormat(locale, { maximumFractionDigits: 1 }).format(value)} ${units[exponent - 1]}`;
}
