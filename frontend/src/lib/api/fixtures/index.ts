import caseOverviewFixture from "./case-001.json";
import evidenceFixture from "./case-001-evidence.json";
import emptyCasesFixture from "./empty-cases.json";
import narrativesFixture from "./narratives.json";
import negativeResponsesFixture from "./negative-responses.json";

import type {
  CaseOverview,
  CaseSummary,
  EvidenceArtifact,
  ApiError,
  NarrativeAnswer,
  SystemHealth,
} from "../contracts";

export const case001 = caseOverviewFixture as CaseOverview;
export const case001Evidence = evidenceFixture as unknown as readonly EvidenceArtifact[];
export const case001Narratives = narrativesFixture as Readonly<Record<string, NarrativeAnswer>>;

export const caseSummaries: readonly CaseSummary[] = [
  {
    case_id: case001.case_id,
    verdict: case001.authoritative_result.verdict,
    seal_status: case001.seal.status,
    updated_at: case001.audit.checked_at,
  },
];

export const operationalHealth: SystemHealth = {
  status: "OPERATIONAL",
  engine: "AVAILABLE",
  ollama: "NOT_CONFIGURED",
};

export const emptyCaseSummaries = emptyCasesFixture as readonly CaseSummary[];

export const mockErrors = negativeResponsesFixture as Readonly<Record<string, ApiError>>;

export const unavailableHealth: SystemHealth = {
  status: "UNAVAILABLE",
  engine: "UNAVAILABLE",
  ollama: "UNAVAILABLE",
};
