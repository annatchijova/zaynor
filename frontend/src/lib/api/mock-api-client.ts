import { ApiClientError } from "./api-client-error";
import type { ZaynorApiClient } from "./api-client";
import {
  case001,
  case001Evidence,
  case001Narratives,
  caseSummaries,
  demoCaseEvidence,
  demoCases,
  emptyCaseSummaries,
  mockErrors,
  operationalHealth,
} from "./fixtures";
import type {
  AuthoritativeResult,
  ApiError,
  AuditStatus,
  CaseOverview,
  CaseSummary,
  EvidenceArtifact,
  InvestigationProposal,
  InvestigationRequest,
  InvestigationSummary,
  NarrativeAnswer,
  ReportArtifact,
  ReportFormat,
  SystemHealth,
} from "./contracts";

export interface MockApiDataset {
  readonly cases: readonly CaseOverview[];
  readonly caseSummaries: readonly CaseSummary[];
  readonly evidenceByCase: Readonly<Record<string, readonly EvidenceArtifact[]>>;
  readonly health: SystemHealth;
  readonly narrativesByCase: Readonly<Record<string, Readonly<Record<string, NarrativeAnswer>>>>;
  readonly narrationError?: ApiError;
}

export const defaultMockDataset: MockApiDataset = {
  cases: [case001, ...demoCases],
  caseSummaries,
  evidenceByCase: {
    [case001.case_id]: case001Evidence,
    ...demoCaseEvidence,
  },
  health: operationalHealth,
  narrativesByCase: {
    // Assistance chat narration is only prepared for case001 today; the demo
    // corpus's other cases correctly surface INVALID_REQUEST from
    // MockApiClient.explain() rather than a fabricated narrative.
    [case001.case_id]: case001Narratives,
  },
};

export const emptyMockDataset: MockApiDataset = {
  cases: [],
  caseSummaries: emptyCaseSummaries,
  evidenceByCase: {},
  health: operationalHealth,
  narrativesByCase: {},
};

export const unavailableNarrationMockDataset: MockApiDataset = {
  ...defaultMockDataset,
  narrationError: mockErrors.ollama_unavailable,
};

export const rejectedNarrationMockDataset: MockApiDataset = {
  ...defaultMockDataset,
  narrationError: mockErrors.policy_rejected,
};

function clone<T>(value: T): T {
  return structuredClone(value);
}

function normalizeQuestion(question: string): string {
  return question.trim().toLocaleLowerCase("es-AR");
}

function narrativeKey(question: string): string | null {
  const normalizedQuestion = normalizeQuestion(question);

  if (normalizedQuestion.includes("qué pasó") || normalizedQuestion.includes("que paso")) {
    return "what_happened";
  }

  if (normalizedQuestion.includes("por qué") || normalizedQuestion.includes("por que")) {
    return "why_suspicious";
  }

  if (normalizedQuestion.includes("qué evidencia") || normalizedQuestion.includes("que evidencia")) {
    return "supporting_evidence";
  }

  if (normalizedQuestion.includes("qué todavía") || normalizedQuestion.includes("que todavia")) {
    return "unknowns";
  }

  if (normalizedQuestion.includes("qué debería") || normalizedQuestion.includes("que deberia")) {
    return "next_step";
  }

  return null;
}

function fixtureError(key: "case_not_found" | "invalid_request"): ApiClientError {
  return new ApiClientError(mockErrors[key]);
}

export class MockApiClient implements ZaynorApiClient {
  readonly #cases = new Map<string, CaseOverview>();
  readonly #caseSummaries: readonly CaseSummary[];
  readonly #evidenceByCase: Readonly<Record<string, readonly EvidenceArtifact[]>>;
  readonly #health: SystemHealth;
  readonly #narrativesByCase: Readonly<Record<string, Readonly<Record<string, NarrativeAnswer>>>>;
  readonly #narrationError: ApiError | undefined;

  constructor(dataset: MockApiDataset = defaultMockDataset) {
    for (const caseOverview of dataset.cases) {
      this.#cases.set(caseOverview.case_id, clone(caseOverview));
    }

    this.#caseSummaries = clone(dataset.caseSummaries);
    this.#evidenceByCase = clone(dataset.evidenceByCase);
    this.#health = clone(dataset.health);
    this.#narrativesByCase = clone(dataset.narrativesByCase);
    this.#narrationError = dataset.narrationError ? clone(dataset.narrationError) : undefined;
  }

  async getHealth(): Promise<SystemHealth> {
    return clone(this.#health);
  }

  async listCases(): Promise<readonly CaseSummary[]> {
    return clone(this.#caseSummaries);
  }

  async getCase(caseId: string): Promise<CaseOverview> {
    return clone(this.#requireCase(caseId));
  }

  async getAuthoritativeResult(caseId: string): Promise<AuthoritativeResult> {
    return clone(this.#requireCase(caseId).authoritative_result);
  }

  async getAudit(caseId: string): Promise<AuditStatus> {
    return clone(this.#requireCase(caseId).audit);
  }

  async getEvidence(caseId: string): Promise<readonly EvidenceArtifact[]> {
    this.#requireCase(caseId);
    return clone(this.#evidenceByCase[caseId] ?? []);
  }

  async getInvestigationSession(caseId: string): Promise<InvestigationSummary> {
    return clone(this.#requireCase(caseId).investigation);
  }

  async proposeInvestigation(
    caseId: string,
    request: InvestigationRequest,
  ): Promise<InvestigationProposal> {
    const caseOverview = this.#requireCase(caseId);
    const question = request.question.trim();

    if (!question) {
      throw fixtureError("invalid_request");
    }

    const proposal: InvestigationProposal = {
      proposal_id: `P${String(caseOverview.investigation.proposals.length + 1).padStart(3, "0")}`,
      case_id: caseId,
      question,
      rationale: "Propuesta registrada por la API mock. No tiene efecto autoritativo.",
      requested_tool: "verify_custody",
      capability: "pending_policy_evaluation",
      arguments_digest: "mock-request-digest",
      information_sought: "Pendiente de evaluación de política.",
      status: "PROPOSED",
      created_at: "2026-09-17T00:00:00Z",
    };

    this.#cases.set(caseId, {
      ...caseOverview,
      investigation: {
        ...caseOverview.investigation,
        status: "OPEN",
        proposals: [...caseOverview.investigation.proposals, proposal],
        authoritative_result_unchanged: true,
      },
    });

    return clone(proposal);
  }

  async explain(caseId: string, question: string): Promise<NarrativeAnswer> {
    this.#requireCase(caseId);

    if (this.#narrationError) {
      throw new ApiClientError(this.#narrationError);
    }

    const key = narrativeKey(question);
    const narrative = key ? this.#narrativesByCase[caseId]?.[key] : undefined;

    if (!narrative) {
      throw fixtureError("invalid_request");
    }

    return clone(narrative);
  }

  async getReport(caseId: string, format: ReportFormat): Promise<ReportArtifact> {
    this.#requireCase(caseId);

    const contentTypes: Record<ReportFormat, string> = {
      md: "text/markdown",
      html: "text/html",
      pdf: "application/pdf",
    };

    return {
      format,
      content_type: contentTypes[format],
      download_url: `mock://reports/${caseId}.${format}`,
    };
  }

  #requireCase(caseId: string): CaseOverview {
    const caseOverview = this.#cases.get(caseId);

    if (caseOverview) {
      return caseOverview;
    }

    throw fixtureError("case_not_found");
  }
}
