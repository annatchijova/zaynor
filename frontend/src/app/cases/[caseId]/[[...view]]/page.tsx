import { notFound } from "next/navigation";
import { Suspense } from "react";

import { AuditSummary } from "@/components/case/audit-summary";
import { CaseNavigation } from "@/components/case/case-navigation";
import { CaseOverviewView } from "@/components/case/case-overview";
import { EvidenceTable } from "@/components/case/evidence-table";
import { JuniorChat } from "@/components/chat/junior-chat";
import { InvestigationQueue } from "@/components/investigation/investigation-queue";
import { ReportsView } from "@/components/reports/reports-view";
import { SeniorConsole } from "@/components/senior/senior-console";
import { IntegrityBadge } from "@/components/ui/integrity-badge";
import { StatePanel } from "@/components/ui/state-panel";
import { ApiClientError, api } from "@/lib/api";
import type { CaseOverview, EvidenceArtifact } from "@/lib/api";

import styles from "@/components/case/case-workspace.module.css";

interface CaseRouteProps {
  readonly params: Promise<{
    readonly caseId: string;
    readonly view?: readonly string[];
  }>;
}

function CaseRouteFallback() {
  return (
    <div className="route-placeholder">
      <StatePanel
        detail="Preparando el contexto autoritativo del caso."
        title="Cargando caso"
        tone="loading"
      />
    </div>
  );
}

function EvidenceView({
  caseId,
  caseOverview,
  evidence,
}: {
  readonly caseId: string;
  readonly caseOverview: CaseOverview;
  readonly evidence: readonly EvidenceArtifact[];
}) {
  return (
    <div className={styles.workspace}>
      <header className={styles.caseHeader}>
        <div>
          <p className={styles.eyebrow}>Evidencia congelada</p>
          <h1>{caseId}</h1>
          <p>{evidence.length} artefactos incluidos en el snapshot verificado.</p>
        </div>
        <IntegrityBadge label="Manifest" status={caseOverview.snapshot.status} />
      </header>
      <CaseNavigation activeView="evidence" caseId={caseId} />
      <EvidenceTable evidence={evidence} />
    </div>
  );
}

function ChatView({ caseOverview }: { readonly caseOverview: CaseOverview }) {
  const { authoritative_result: result, case_id: caseId, seal } = caseOverview;

  return (
    <>
      <div className={styles.workspace}>
        <CaseNavigation activeView="chat" caseId={caseId} />
      </div>
      <JuniorChat caseId={caseId} sealStatus={seal.status} verdict={result.verdict} />
    </>
  );
}

async function loadCase(caseId: string): Promise<CaseOverview> {
  try {
    return await api.getCase(caseId);
  } catch (error) {
    if (error instanceof ApiClientError && error.code === "CASE_NOT_FOUND") {
      notFound();
    }

    throw error;
  }
}

async function loadEvidence(caseId: string) {
  try {
    const [caseOverview, evidence] = await Promise.all([api.getCase(caseId), api.getEvidence(caseId)]);
    return { caseOverview, evidence };
  } catch (error) {
    if (error instanceof ApiClientError && error.code === "CASE_NOT_FOUND") {
      notFound();
    }

    throw error;
  }
}

async function loadReports(caseId: string) {
  try {
    const [caseOverview, ...reports] = await Promise.all([
      api.getCase(caseId),
      api.getReport(caseId, "md"),
      api.getReport(caseId, "html"),
      api.getReport(caseId, "pdf"),
    ]);
    return { caseOverview, reports };
  } catch (error) {
    if (error instanceof ApiClientError && error.code === "CASE_NOT_FOUND") {
      notFound();
    }

    throw error;
  }
}

async function CaseWorkspace({ params }: CaseRouteProps) {
  const { caseId, view } = await params;
  const activeView = view?.[0];

  if (activeView === "evidence" || activeView === "senior") {
    const { caseOverview, evidence } = await loadEvidence(caseId);

    if (activeView === "senior") {
      return <SeniorConsole caseOverview={caseOverview} evidence={evidence} />;
    }

    return <EvidenceView caseId={caseId} caseOverview={caseOverview} evidence={evidence} />;
  }

  if (activeView === "reports") {
    const { caseOverview, reports } = await loadReports(caseId);
    return <ReportsView caseOverview={caseOverview} reports={reports} />;
  }

  const caseOverview = await loadCase(caseId);

  if (activeView === "chat") {
    return <ChatView caseOverview={caseOverview} />;
  }

  if (activeView === "investigation") {
    return <InvestigationQueue caseOverview={caseOverview} />;
  }

  if (activeView === "audit") {
    return (
      <AuditSummary
        audit={caseOverview.audit}
        caseId={caseId}
        result={caseOverview.authoritative_result}
        seal={caseOverview.seal}
        snapshot={caseOverview.snapshot}
      />
    );
  }

  return <CaseOverviewView caseOverview={caseOverview} />;
}

export default function CaseRoute({ params }: CaseRouteProps) {
  return (
    <Suspense fallback={<CaseRouteFallback />}>
      <CaseWorkspace params={params} />
    </Suspense>
  );
}
