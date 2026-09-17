export type Verdict =
  | "MALICE"
  | "SUSPICION"
  | "ABSTAIN"
  | "UNKNOWN"
  | "BENIGN";

export type ClaimState = "CORROBORATED" | "CONTRADICTED" | "INSUFFICIENT";

export type FindingState = Verdict | ClaimState;

export type VerificationStatus = "VERIFIED" | "FAILED" | "UNKNOWN";

export type Confidence = "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN";

export type ProposalStatus = "PROPOSED" | "APPROVED" | "REJECTED" | "EXECUTED";

export type ObservationStatus = "OBSERVED" | "UNTRUSTED" | "FAILED" | "REJECTED";

export type NarrativeCertainty = "AUTHORIZED" | "LIMITED" | "UNKNOWN";

export type ReportFormat = "md" | "html" | "pdf";

export type JsonPrimitive = boolean | number | string | null;

export type JsonValue = JsonPrimitive | JsonValue[] | { readonly [key: string]: JsonValue };

export interface EvidenceRef {
  readonly artifact: string;
  readonly lineage_id: string;
}

export interface CaseSummary {
  readonly case_id: string;
  readonly name: string | null;
  readonly verdict: Verdict;
  readonly seal_status: VerificationStatus;
  readonly updated_at: string | null;
}

export interface SnapshotStatus {
  readonly status: VerificationStatus;
  readonly manifest_sha256: string;
  readonly evidence_set_sha256: string;
  readonly artifact_count: number;
  readonly sealed_at: string | null;
}

export interface SealStatus {
  readonly status: VerificationStatus;
  readonly result_sha256: string;
  readonly canonicalize_version: string;
}

export interface AuditStatus {
  readonly status: VerificationStatus;
  readonly manifest: VerificationStatus;
  readonly snapshot: VerificationStatus;
  readonly evidence: VerificationStatus;
  readonly result: VerificationStatus;
  readonly seal: VerificationStatus;
  readonly provenance: "PRESENT" | "EMPTY" | "UNKNOWN";
  readonly checked_at: string | null;
  readonly detail: string | null;
}

export interface Finding {
  readonly finding_id: string;
  readonly state: FindingState;
  readonly rationale: string;
  readonly evidence_refs: readonly EvidenceRef[];
  readonly lineage_ids: readonly string[];
  readonly mitre: Readonly<Record<string, JsonValue>> | null;
  readonly nist: Readonly<Record<string, JsonValue>> | null;
}

export interface Unknown {
  readonly id: string;
  readonly statement: string;
  readonly what_would_resolve: string | null;
}

export interface Hypothesis {
  readonly hypothesis_id: string;
  readonly statement: string;
  readonly status: "OPEN" | "SUPPORTED" | "REFUTED" | "UNKNOWN";
  readonly rationale: string | null;
}

export interface Fracture {
  readonly fracture_id: string;
  readonly type: string;
  readonly severity: string | null;
  readonly description: string;
  readonly evidence_refs: readonly EvidenceRef[];
}

export interface Signal {
  readonly signal_id: string;
  readonly artifact: string | null;
  readonly source: string;
  readonly score: string | null;
  readonly confidence: string | null;
  readonly metadata: Readonly<Record<string, JsonValue>>;
}

export interface AuthoritativeResult {
  readonly case_id: string;
  readonly verdict: Verdict;
  readonly confidence: Confidence;
  readonly findings: readonly Finding[];
  readonly unknowns: readonly Unknown[];
  readonly hypotheses: readonly Hypothesis[];
  readonly fractures: readonly Fracture[];
  readonly signals: readonly Signal[];
  readonly result_sha256: string;
  readonly engine: {
    readonly name: string;
    readonly version: string;
    readonly configuration_hash: string;
  };
  readonly audit_refs: readonly string[];
}

export interface EvidenceArtifact {
  readonly evidence_id: string;
  readonly type: string;
  readonly source: string;
  readonly relative_path: string;
  readonly sha256: string;
  readonly size_bytes: number;
  readonly manifest_status: VerificationStatus;
  readonly lineage_id: string;
  readonly provenance: readonly ProvenanceEntry[];
  readonly finding_refs: readonly string[];
  readonly metadata: Readonly<Record<string, JsonValue>>;
}

export interface ProvenanceEntry {
  readonly label: string;
  readonly value: string;
  readonly status: VerificationStatus | "DECLARED" | "UNAVAILABLE";
}

export interface InvestigationProposal {
  readonly proposal_id: string;
  readonly case_id: string;
  readonly question: string;
  readonly rationale: string;
  readonly requested_tool: string;
  readonly capability: string;
  readonly arguments_digest: string;
  readonly information_sought: string;
  readonly status: ProposalStatus;
  readonly created_at: string;
}

export interface Observation {
  readonly observation_id: string;
  readonly case_id: string;
  readonly proposal_id: string;
  readonly tool_name: string;
  readonly capability: string;
  readonly arguments_digest: string;
  readonly payload_sha256: string;
  readonly payload: JsonValue | null;
  readonly status: ObservationStatus;
  readonly recorded_at: string;
}

export interface InvestigationSummary {
  readonly session_id: string | null;
  readonly status: "OPEN" | "BLOCKED" | "COMPLETE" | "NOT_STARTED";
  readonly proposals: readonly InvestigationProposal[];
  readonly observations: readonly Observation[];
  readonly authoritative_result_unchanged: boolean;
}

export interface InvestigationRequest {
  // Matches the real backend contract exactly: POST
  // /cases/{case_id}/investigations/proposals only ever accepts a
  // question. The LLM proposes which tool to call and with what
  // arguments; a human does not pick them here. (Older code in this
  // client sent `requested_tool`/`arguments` too — the backend's Pydantic
  // model silently ignored them, since it never declared those fields.)
  readonly question: string;
}

export interface NarrativeAnswer {
  readonly narrative: string;
  readonly finding_refs: readonly string[];
  readonly evidence_refs: readonly EvidenceRef[];
  readonly certainty: NarrativeCertainty;
  readonly disclaimer: string;
}

export interface ReportArtifact {
  readonly format: ReportFormat;
  readonly content_type: string;
  readonly download_url: string;
}

export interface CaseOverview {
  readonly case_id: string;
  readonly snapshot: SnapshotStatus;
  readonly authoritative_result: AuthoritativeResult;
  readonly seal: SealStatus;
  readonly audit: AuditStatus;
  readonly investigation: InvestigationSummary;
}

export interface SystemHealth {
  readonly status: "OPERATIONAL" | "DEGRADED" | "UNAVAILABLE";
  readonly engine: "AVAILABLE" | "UNAVAILABLE";
  readonly ollama: "AVAILABLE" | "UNAVAILABLE" | "NOT_CONFIGURED";
}

export interface ApiError {
  readonly code:
    | "CASE_NOT_FOUND"
    | "INVALID_REQUEST"
    | "SEAL_VERIFICATION_FAILED"
    | "AUDIT_FAILED"
    | "OLLAMA_UNAVAILABLE"
    | "POLICY_REJECTED"
    | "INTERNAL_ERROR";
  readonly message: string;
  readonly request_id: string | null;
}
