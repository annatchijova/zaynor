import type { CaseOverview } from "@/lib/api";
import { formatDateTime } from "@/lib/presentation/formatters";

import { CaseNavigation } from "@/components/case/case-navigation";
import { IntegrityBadge } from "@/components/ui/integrity-badge";

import { InvestigationTimeline } from "./investigation-timeline";

import styles from "./investigation-queue.module.css";

interface InvestigationQueueProps {
  readonly caseOverview: CaseOverview;
}

export function InvestigationQueue({ caseOverview }: InvestigationQueueProps) {
  const { authoritative_result: result, case_id: caseId, investigation, seal } = caseOverview;
  const hasObservation = investigation.observations.length > 0;

  return (
    <div className={styles.workspace}>
      <header className={styles.header}>
        <div>
          <p className={styles.eyebrow}>Cola de investigación</p>
          <h1>{caseId}</h1>
          <p>Secuencia read-only separada del análisis determinista y del resultado sellado.</p>
        </div>
        <IntegrityBadge label="Sello vigente" status={seal.status} />
      </header>

      <CaseNavigation activeView="investigation" caseId={caseId} />

      <section aria-label="Límite de autoridad" className={styles.authorityBoundary}>
        <div>
          <span>Propuesta</span>
          <strong>No es un hallazgo</strong>
        </div>
        <div>
          <span>Observación</span>
          <strong>No es un veredicto</strong>
        </div>
        <div>
          <span>Modelo local</span>
          <strong>No es autoridad</strong>
        </div>
      </section>

      <section aria-labelledby="investigation-status-title" className={styles.resultState}>
        <div>
          <p className={styles.eyebrow}>Estado de la sesión</p>
          <h2 id="investigation-status-title">{investigation.status}</h2>
          <p>Sesión: {investigation.session_id ?? "No iniciada"}</p>
        </div>
        <div className={styles.resultStateLabels}>
          {hasObservation ? <strong>OBSERVATION_RECORDED</strong> : <strong>NO_OBSERVATION_RECORDED</strong>}
          <strong>
            {investigation.authoritative_result_unchanged
              ? "AUTHORITATIVE_RESULT_UNCHANGED"
              : "AUTHORITATIVE_RESULT_UPDATE_NOT_SUPPLIED"}
          </strong>
        </div>
        <p>
          Resultado vigente: {result.verdict}. Último sello verificado: {formatDateTime(caseOverview.audit.checked_at)}.
        </p>
      </section>

      <section aria-labelledby="timeline-title" className={styles.section}>
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>Propuesta → policy → herramienta → observación</p>
          <h2 id="timeline-title">Secuencia registrada</h2>
        </div>
        <InvestigationTimeline investigation={investigation} />
      </section>
    </div>
  );
}
