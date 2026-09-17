import type {
  AuthoritativeResult,
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

export interface ZaynorApiClient {
  getHealth(): Promise<SystemHealth>;
  listCases(): Promise<readonly CaseSummary[]>;
  getCase(caseId: string): Promise<CaseOverview>;
  getAuthoritativeResult(caseId: string): Promise<AuthoritativeResult>;
  getAudit(caseId: string): Promise<AuditStatus>;
  getEvidence(caseId: string): Promise<readonly EvidenceArtifact[]>;
  getInvestigationSession(caseId: string): Promise<InvestigationSummary>;
  proposeInvestigation(
    caseId: string,
    request: InvestigationRequest,
  ): Promise<InvestigationProposal>;
  explain(caseId: string, question: string): Promise<NarrativeAnswer>;
  getReport(caseId: string, format: ReportFormat): Promise<ReportArtifact>;
}
