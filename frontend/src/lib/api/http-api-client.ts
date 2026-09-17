import { ApiClientError } from "./api-client-error";
import type { ZaynorApiClient } from "./api-client";
import type {
  ApiError,
  AuthoritativeResult,
  AuditStatus,
  CaseOverview,
  CaseSummary,
  Confidence,
  EvidenceArtifact,
  EvidenceRef,
  Finding,
  FindingState,
  Fracture,
  Hypothesis,
  InvestigationProposal,
  InvestigationRequest,
  InvestigationSummary,
  JsonValue,
  NarrativeAnswer,
  NarrativeCertainty,
  Observation,
  ObservationStatus,
  ProposalStatus,
  ReportArtifact,
  ReportFormat,
  SealStatus,
  Signal,
  SnapshotStatus,
  SystemHealth,
  Unknown,
  Verdict,
} from "./contracts";

type FetchImplementation = (input: string, init?: RequestInit) => Promise<Response>;
type JsonRecord = Readonly<Record<string, unknown>>;

const caseIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

const verdicts = ["MALICE", "SUSPICION", "ABSTAIN", "UNKNOWN", "BENIGN"] as const;
const verificationStatuses = ["VERIFIED", "FAILED", "UNKNOWN"] as const;
const confidences = ["LOW", "MEDIUM", "HIGH", "UNKNOWN"] as const;
const findingStates = [...verdicts, "CORROBORATED", "CONTRADICTED", "INSUFFICIENT"] as const;
const proposalStatuses = ["PROPOSED", "APPROVED", "REJECTED", "EXECUTED"] as const;
const observationStatuses = ["OBSERVED", "UNTRUSTED", "FAILED", "REJECTED"] as const;
const narrativeCertainties = ["AUTHORIZED", "LIMITED", "UNKNOWN"] as const;
const errorCodes = [
  "CASE_NOT_FOUND",
  "INVALID_REQUEST",
  "SEAL_VERIFICATION_FAILED",
  "AUDIT_FAILED",
  "OLLAMA_UNAVAILABLE",
  "POLICY_REJECTED",
  "INTERNAL_ERROR",
] as const;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireRecord(value: unknown, path: string): JsonRecord {
  if (!isRecord(value)) {
    throw new TypeError(`${path} must be an object.`);
  }

  return value;
}

function requireString(value: unknown, path: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`${path} must be a string.`);
  }

  return value;
}

function requireNumber(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new TypeError(`${path} must be a finite number.`);
  }

  return value;
}

function requireNullableString(value: unknown, path: string): string | null {
  return value === null ? null : requireString(value, path);
}

function requireArray(value: unknown, path: string): readonly unknown[] {
  if (!Array.isArray(value)) {
    throw new TypeError(`${path} must be an array.`);
  }

  return value;
}

function requireEnum<T extends string>(value: unknown, allowed: readonly T[], path: string): T {
  const candidate = requireString(value, path);

  if (!allowed.includes(candidate as T)) {
    throw new TypeError(`${path} has an unsupported value.`);
  }

  return candidate as T;
}

function requireJsonValue(value: unknown, path: string): JsonValue {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return value;
  }

  if (typeof value === "number") {
    return requireNumber(value, path);
  }

  if (Array.isArray(value)) {
    return value.map((item, index) => requireJsonValue(item, `${path}[${index}]`));
  }

  const record = requireRecord(value, path);
  return Object.fromEntries(
    Object.entries(record).map(([key, item]) => [key, requireJsonValue(item, `${path}.${key}`)]),
  );
}

function requireJsonRecord(value: unknown, path: string): Readonly<Record<string, JsonValue>> {
  const record = requireRecord(value, path);
  return Object.fromEntries(
    Object.entries(record).map(([key, item]) => [key, requireJsonValue(item, `${path}.${key}`)]),
  );
}

function parseEvidenceRef(value: unknown, path: string): EvidenceRef {
  const record = requireRecord(value, path);
  return {
    artifact: requireString(record.artifact, `${path}.artifact`),
    lineage_id: requireString(record.lineage_id, `${path}.lineage_id`),
  };
}

function parseSnapshotStatus(value: unknown): SnapshotStatus {
  const record = requireRecord(value, "snapshot");
  return {
    status: requireEnum(record.status, verificationStatuses, "snapshot.status"),
    manifest_sha256: requireString(record.manifest_sha256, "snapshot.manifest_sha256"),
    evidence_set_sha256: requireString(record.evidence_set_sha256, "snapshot.evidence_set_sha256"),
    artifact_count: requireNumber(record.artifact_count, "snapshot.artifact_count"),
    sealed_at: requireNullableString(record.sealed_at, "snapshot.sealed_at"),
  };
}

function parseFinding(value: unknown, path: string): Finding {
  const record = requireRecord(value, path);
  return {
    finding_id: requireString(record.finding_id, `${path}.finding_id`),
    state: requireEnum(record.state, findingStates, `${path}.state`) as FindingState,
    rationale: requireString(record.rationale, `${path}.rationale`),
    evidence_refs: requireArray(record.evidence_refs, `${path}.evidence_refs`).map((reference, index) =>
      parseEvidenceRef(reference, `${path}.evidence_refs[${index}]`),
    ),
    lineage_ids: requireArray(record.lineage_ids, `${path}.lineage_ids`).map((lineageId, index) =>
      requireString(lineageId, `${path}.lineage_ids[${index}]`),
    ),
    mitre: record.mitre === null ? null : requireJsonRecord(record.mitre, `${path}.mitre`),
    nist: record.nist === null ? null : requireJsonRecord(record.nist, `${path}.nist`),
  };
}

function parseUnknown(value: unknown, path: string): Unknown {
  const record = requireRecord(value, path);
  return {
    id: requireString(record.id, `${path}.id`),
    statement: requireString(record.statement, `${path}.statement`),
    what_would_resolve: requireNullableString(record.what_would_resolve, `${path}.what_would_resolve`),
  };
}

function parseHypothesis(value: unknown, path: string): Hypothesis {
  const record = requireRecord(value, path);
  return {
    hypothesis_id: requireString(record.hypothesis_id, `${path}.hypothesis_id`),
    statement: requireString(record.statement, `${path}.statement`),
    status: requireEnum(record.status, ["OPEN", "SUPPORTED", "REFUTED", "UNKNOWN"], `${path}.status`),
    rationale: requireNullableString(record.rationale, `${path}.rationale`),
  };
}

function parseFracture(value: unknown, path: string): Fracture {
  const record = requireRecord(value, path);
  return {
    fracture_id: requireString(record.fracture_id, `${path}.fracture_id`),
    type: requireString(record.type, `${path}.type`),
    severity: requireNullableString(record.severity, `${path}.severity`),
    description: requireString(record.description, `${path}.description`),
    evidence_refs: requireArray(record.evidence_refs, `${path}.evidence_refs`).map((reference, index) =>
      parseEvidenceRef(reference, `${path}.evidence_refs[${index}]`),
    ),
  };
}

function parseSignal(value: unknown, path: string): Signal {
  const record = requireRecord(value, path);
  return {
    signal_id: requireString(record.signal_id, `${path}.signal_id`),
    artifact: requireNullableString(record.artifact, `${path}.artifact`),
    source: requireString(record.source, `${path}.source`),
    score: requireNullableString(record.score, `${path}.score`),
    confidence: requireNullableString(record.confidence, `${path}.confidence`),
    metadata: requireJsonRecord(record.metadata, `${path}.metadata`),
  };
}

function parseAuthoritativeResult(value: unknown): AuthoritativeResult {
  const record = requireRecord(value, "authoritative_result");
  const engine = requireRecord(record.engine, "authoritative_result.engine");
  return {
    case_id: requireString(record.case_id, "authoritative_result.case_id"),
    verdict: requireEnum(record.verdict, verdicts, "authoritative_result.verdict") as Verdict,
    confidence: requireEnum(record.confidence, confidences, "authoritative_result.confidence") as Confidence,
    findings: requireArray(record.findings, "authoritative_result.findings").map((finding, index) =>
      parseFinding(finding, `authoritative_result.findings[${index}]`),
    ),
    unknowns: requireArray(record.unknowns, "authoritative_result.unknowns").map((unknown, index) =>
      parseUnknown(unknown, `authoritative_result.unknowns[${index}]`),
    ),
    hypotheses: requireArray(record.hypotheses, "authoritative_result.hypotheses").map((hypothesis, index) =>
      parseHypothesis(hypothesis, `authoritative_result.hypotheses[${index}]`),
    ),
    fractures: requireArray(record.fractures, "authoritative_result.fractures").map((fracture, index) =>
      parseFracture(fracture, `authoritative_result.fractures[${index}]`),
    ),
    signals: requireArray(record.signals, "authoritative_result.signals").map((signal, index) =>
      parseSignal(signal, `authoritative_result.signals[${index}]`),
    ),
    result_sha256: requireString(record.result_sha256, "authoritative_result.result_sha256"),
    engine: {
      name: requireString(engine.name, "authoritative_result.engine.name"),
      version: requireString(engine.version, "authoritative_result.engine.version"),
      configuration_hash: requireString(engine.configuration_hash, "authoritative_result.engine.configuration_hash"),
    },
    audit_refs: requireArray(record.audit_refs, "authoritative_result.audit_refs").map((reference, index) =>
      requireString(reference, `authoritative_result.audit_refs[${index}]`),
    ),
  };
}

function parseSealStatus(value: unknown): SealStatus {
  const record = requireRecord(value, "seal");
  return {
    status: requireEnum(record.status, verificationStatuses, "seal.status"),
    result_sha256: requireString(record.result_sha256, "seal.result_sha256"),
    canonicalize_version: requireString(record.canonicalize_version, "seal.canonicalize_version"),
  };
}

function parseAuditStatus(value: unknown): AuditStatus {
  const record = requireRecord(value, "audit");
  return {
    status: requireEnum(record.status, verificationStatuses, "audit.status"),
    manifest: requireEnum(record.manifest, verificationStatuses, "audit.manifest"),
    snapshot: requireEnum(record.snapshot, verificationStatuses, "audit.snapshot"),
    evidence: requireEnum(record.evidence, verificationStatuses, "audit.evidence"),
    result: requireEnum(record.result, verificationStatuses, "audit.result"),
    seal: requireEnum(record.seal, verificationStatuses, "audit.seal"),
    provenance: requireEnum(record.provenance, ["PRESENT", "EMPTY", "UNKNOWN"], "audit.provenance"),
    checked_at: requireNullableString(record.checked_at, "audit.checked_at"),
    detail: requireNullableString(record.detail, "audit.detail"),
  };
}

function parseProposal(value: unknown, path = "proposal"): InvestigationProposal {
  const record = requireRecord(value, path);
  return {
    proposal_id: requireString(record.proposal_id, `${path}.proposal_id`),
    case_id: requireString(record.case_id, `${path}.case_id`),
    question: requireString(record.question, `${path}.question`),
    rationale: requireString(record.rationale, `${path}.rationale`),
    requested_tool: requireString(record.requested_tool, `${path}.requested_tool`),
    capability: requireString(record.capability, `${path}.capability`),
    arguments_digest: requireString(record.arguments_digest, `${path}.arguments_digest`),
    information_sought: requireString(record.information_sought, `${path}.information_sought`),
    status: requireEnum(record.status, proposalStatuses, `${path}.status`) as ProposalStatus,
    created_at: requireString(record.created_at, `${path}.created_at`),
  };
}

function parseObservation(value: unknown, path: string): Observation {
  const record = requireRecord(value, path);
  return {
    observation_id: requireString(record.observation_id, `${path}.observation_id`),
    case_id: requireString(record.case_id, `${path}.case_id`),
    proposal_id: requireString(record.proposal_id, `${path}.proposal_id`),
    tool_name: requireString(record.tool_name, `${path}.tool_name`),
    capability: requireString(record.capability, `${path}.capability`),
    arguments_digest: requireString(record.arguments_digest, `${path}.arguments_digest`),
    payload_sha256: requireString(record.payload_sha256, `${path}.payload_sha256`),
    payload: record.payload === null ? null : requireJsonValue(record.payload, `${path}.payload`),
    status: requireEnum(record.status, observationStatuses, `${path}.status`) as ObservationStatus,
    recorded_at: requireString(record.recorded_at, `${path}.recorded_at`),
  };
}

function parseInvestigationSummary(value: unknown): InvestigationSummary {
  const record = requireRecord(value, "investigation");
  return {
    session_id: requireNullableString(record.session_id, "investigation.session_id"),
    status: requireEnum(record.status, ["OPEN", "BLOCKED", "COMPLETE", "NOT_STARTED"], "investigation.status"),
    proposals: requireArray(record.proposals, "investigation.proposals").map((proposal, index) =>
      parseProposal(proposal, `investigation.proposals[${index}]`),
    ),
    observations: requireArray(record.observations, "investigation.observations").map((observation, index) =>
      parseObservation(observation, `investigation.observations[${index}]`),
    ),
    authoritative_result_unchanged: requireBoolean(
      record.authoritative_result_unchanged,
      "investigation.authoritative_result_unchanged",
    ),
  };
}

function requireBoolean(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") {
    throw new TypeError(`${path} must be a boolean.`);
  }

  return value;
}

function parseCaseOverview(value: unknown): CaseOverview {
  const record = requireRecord(value, "case");
  return {
    case_id: requireString(record.case_id, "case.case_id"),
    snapshot: parseSnapshotStatus(record.snapshot),
    authoritative_result: parseAuthoritativeResult(record.authoritative_result),
    seal: parseSealStatus(record.seal),
    audit: parseAuditStatus(record.audit),
    investigation: parseInvestigationSummary(record.investigation),
  };
}

function parseCaseSummary(value: unknown, path: string): CaseSummary {
  const record = requireRecord(value, path);
  return {
    case_id: requireString(record.case_id, `${path}.case_id`),
    verdict: requireEnum(record.verdict, verdicts, `${path}.verdict`) as Verdict,
    seal_status: requireEnum(record.seal_status, verificationStatuses, `${path}.seal_status`),
    updated_at: requireNullableString(record.updated_at, `${path}.updated_at`),
  };
}

function parseEvidenceArtifact(value: unknown, path: string): EvidenceArtifact {
  const record = requireRecord(value, path);
  return {
    evidence_id: requireString(record.evidence_id, `${path}.evidence_id`),
    type: requireString(record.type, `${path}.type`),
    source: requireString(record.source, `${path}.source`),
    relative_path: requireString(record.relative_path, `${path}.relative_path`),
    sha256: requireString(record.sha256, `${path}.sha256`),
    size_bytes: requireNumber(record.size_bytes, `${path}.size_bytes`),
    manifest_status: requireEnum(record.manifest_status, verificationStatuses, `${path}.manifest_status`),
    lineage_id: requireString(record.lineage_id, `${path}.lineage_id`),
    provenance: requireArray(record.provenance, `${path}.provenance`).map((entry, index) => {
      const provenance = requireRecord(entry, `${path}.provenance[${index}]`);
      return {
        label: requireString(provenance.label, `${path}.provenance[${index}].label`),
        value: requireString(provenance.value, `${path}.provenance[${index}].value`),
        status: requireEnum(
          provenance.status,
          ["VERIFIED", "FAILED", "UNKNOWN", "DECLARED", "UNAVAILABLE"],
          `${path}.provenance[${index}].status`,
        ),
      };
    }),
    finding_refs: requireArray(record.finding_refs, `${path}.finding_refs`).map((reference, index) =>
      requireString(reference, `${path}.finding_refs[${index}]`),
    ),
    metadata: requireJsonRecord(record.metadata, `${path}.metadata`),
  };
}

function parseNarrativeAnswer(value: unknown): NarrativeAnswer {
  const record = requireRecord(value, "narrative");
  return {
    narrative: requireString(record.narrative, "narrative.narrative"),
    finding_refs: requireArray(record.finding_refs, "narrative.finding_refs").map((reference, index) =>
      requireString(reference, `narrative.finding_refs[${index}]`),
    ),
    evidence_refs: requireArray(record.evidence_refs, "narrative.evidence_refs").map((reference, index) =>
      parseEvidenceRef(reference, `narrative.evidence_refs[${index}]`),
    ),
    certainty: requireEnum(record.certainty, narrativeCertainties, "narrative.certainty") as NarrativeCertainty,
    disclaimer: requireString(record.disclaimer, "narrative.disclaimer"),
  };
}

function parseSystemHealth(value: unknown): SystemHealth {
  const record = requireRecord(value, "health");
  return {
    status: requireEnum(record.status, ["OPERATIONAL", "DEGRADED", "UNAVAILABLE"], "health.status"),
    engine: requireEnum(record.engine, ["AVAILABLE", "UNAVAILABLE"], "health.engine"),
    ollama: requireEnum(record.ollama, ["AVAILABLE", "UNAVAILABLE", "NOT_CONFIGURED"], "health.ollama"),
  };
}

function parseReportArtifact(value: unknown): ReportArtifact {
  const record = requireRecord(value, "report");
  return {
    format: requireEnum(record.format, ["md", "html", "pdf"], "report.format") as ReportFormat,
    content_type: requireString(record.content_type, "report.content_type"),
    download_url: requireString(record.download_url, "report.download_url"),
  };
}

function parseApiError(value: unknown): ApiError | null {
  if (!isRecord(value) || typeof value.code !== "string" || !errorCodes.includes(value.code as ApiError["code"])) {
    return null;
  }

  if (typeof value.message !== "string" || (value.request_id !== null && typeof value.request_id !== "string")) {
    return null;
  }

  return {
    code: value.code as ApiError["code"],
    message: value.message,
    request_id: value.request_id,
  };
}

function fallbackError(status: number): ApiError {
  if (status === 404) {
    return { code: "CASE_NOT_FOUND", message: "No se encontró el recurso solicitado.", request_id: null };
  }

  if (status === 400 || status === 422) {
    return { code: "INVALID_REQUEST", message: "La solicitud no cumple el contrato esperado.", request_id: null };
  }

  if (status === 403) {
    return { code: "POLICY_REJECTED", message: "La política rechazó la solicitud.", request_id: null };
  }

  if (status === 503) {
    return { code: "OLLAMA_UNAVAILABLE", message: "El servicio local no está disponible.", request_id: null };
  }

  return { code: "INTERNAL_ERROR", message: "El servicio devolvió una respuesta inesperada.", request_id: null };
}

function assertCaseId(caseId: string): void {
  if (!caseIdPattern.test(caseId)) {
    throw new ApiClientError({
      code: "INVALID_REQUEST",
      message: "El identificador del caso no cumple el formato permitido.",
      request_id: null,
    });
  }
}

export interface HttpApiClientOptions {
  readonly baseUrl: string;
  readonly fetchImplementation?: FetchImplementation;
}

export class HttpApiClient implements ZaynorApiClient {
  readonly #baseUrl: string;
  readonly #fetch: FetchImplementation;

  constructor({ baseUrl, fetchImplementation = globalThis.fetch.bind(globalThis) }: HttpApiClientOptions) {
    const parsedBaseUrl = new URL(baseUrl);

    if (parsedBaseUrl.protocol !== "http:" && parsedBaseUrl.protocol !== "https:") {
      throw new TypeError("The API base URL must use HTTP or HTTPS.");
    }

    this.#baseUrl = parsedBaseUrl.toString().replace(/\/$/, "");
    this.#fetch = fetchImplementation;
  }

  async getHealth(): Promise<SystemHealth> {
    return this.#request("/health", { method: "GET" }, parseSystemHealth);
  }

  async listCases(): Promise<readonly CaseSummary[]> {
    return this.#request("/cases", { method: "GET" }, (payload) => {
      const record = requireRecord(payload, "cases");
      return requireArray(record.cases, "cases.cases").map((summary, index) => parseCaseSummary(summary, `cases.cases[${index}]`));
    });
  }

  async getCase(caseId: string): Promise<CaseOverview> {
    return this.#getCaseResource(caseId, "", parseCaseOverview);
  }

  async getAuthoritativeResult(caseId: string): Promise<AuthoritativeResult> {
    return this.#getCaseResource(caseId, "/result", parseAuthoritativeResult);
  }

  async getAudit(caseId: string): Promise<AuditStatus> {
    return this.#getCaseResource(caseId, "/audit", parseAuditStatus);
  }

  async getEvidence(caseId: string): Promise<readonly EvidenceArtifact[]> {
    return this.#getCaseResource(caseId, "/evidence", (payload) => {
      const record = requireRecord(payload, "evidence");
      return requireArray(record.evidence, "evidence.evidence").map((artifact, index) =>
        parseEvidenceArtifact(artifact, `evidence.evidence[${index}]`),
      );
    });
  }

  async getInvestigationSession(caseId: string): Promise<InvestigationSummary> {
    return this.#getCaseResource(caseId, "/investigation", parseInvestigationSummary);
  }

  async proposeInvestigation(caseId: string, request: InvestigationRequest): Promise<InvestigationProposal> {
    assertCaseId(caseId);
    return this.#request(
      `/cases/${encodeURIComponent(caseId)}/investigations/proposals`,
      { method: "POST", body: JSON.stringify(request) },
      parseProposal,
    );
  }

  async explain(caseId: string, question: string): Promise<NarrativeAnswer> {
    assertCaseId(caseId);
    return this.#request(
      `/cases/${encodeURIComponent(caseId)}/chat`,
      { method: "POST", body: JSON.stringify({ question }) },
      parseNarrativeAnswer,
    );
  }

  async getReport(caseId: string, format: ReportFormat): Promise<ReportArtifact> {
    return this.#getCaseResource(caseId, `/reports/${format}`, parseReportArtifact);
  }

  async #getCaseResource<T>(caseId: string, suffix: string, parser: (payload: unknown) => T): Promise<T> {
    assertCaseId(caseId);
    return this.#request(`/cases/${encodeURIComponent(caseId)}${suffix}`, { method: "GET" }, parser);
  }

  async #request<T>(path: string, init: RequestInit, parser: (payload: unknown) => T): Promise<T> {
    let response: Response;

    try {
      response = await this.#fetch(`${this.#baseUrl}${path}`, {
        ...init,
        headers: {
          Accept: "application/json",
          ...(init.body ? { "Content-Type": "application/json" } : {}),
          ...init.headers,
        },
      });
    } catch {
      throw new ApiClientError({
        code: "INTERNAL_ERROR",
        message: "No se pudo establecer comunicación con el servicio local.",
        request_id: null,
      });
    }

    let payload: unknown;

    try {
      payload = await this.#readPayload(response);
    } catch {
      throw new ApiClientError({
        code: "INTERNAL_ERROR",
        message: "No se pudo leer la respuesta del servicio local.",
        request_id: null,
      });
    }

    if (!response.ok) {
      throw new ApiClientError(parseApiError(payload) ?? fallbackError(response.status));
    }

    try {
      return parser(payload);
    } catch {
      throw new ApiClientError({
        code: "INTERNAL_ERROR",
        message: "El servicio respondió con un payload incompatible con el contrato del frontend.",
        request_id: null,
      });
    }
  }

  async #readPayload(response: Response): Promise<unknown> {
    const body = await response.text();

    if (!body) {
      return null;
    }

    try {
      return JSON.parse(body) as unknown;
    } catch {
      return null;
    }
  }
}
