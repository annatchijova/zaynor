import type { CaseOverview, ReportArtifact } from "@/lib/api";
import { formatDateTime, formatHash } from "@/lib/presentation/formatters";

import { CaseNavigation } from "@/components/case/case-navigation";
import { IntegrityBadge } from "@/components/ui/integrity-badge";
import { VerdictPill } from "@/components/ui/verdict-pill";

import { ReportLinks } from "./report-links";

import styles from "./reports-view.module.css";

interface ReportsViewProps {
  readonly caseOverview: CaseOverview;
  readonly reports: readonly ReportArtifact[];
}

export function ReportsView({ caseOverview, reports }: ReportsViewProps) {
  const { audit, authoritative_result: result, case_id: caseId, seal } = caseOverview;

  return (
    <div className={styles.workspace}>
      <header className={styles.header}>
        <div>
          <p className={styles.eyebrow}>Reportes de caso</p>
          <h1>{caseId}</h1>
          <p>Presentación de artefactos ya emitidos por el backend sobre el resultado sellado.</p>
        </div>
        <div className={styles.status}>
          <VerdictPill verdict={result.verdict} />
          <IntegrityBadge label="Sello" status={seal.status} />
        </div>
      </header>

      <CaseNavigation activeView="reports" caseId={caseId} />

      <section aria-labelledby="report-binding-title" className={styles.binding}>
        <div>
          <p className={styles.eyebrow}>Vinculación autoritativa</p>
          <h2 id="report-binding-title">El reporte representa un resultado ya sellado</h2>
        </div>
        <dl>
          <div>
            <dt>Result SHA-256</dt>
            <dd>{formatHash(result.result_sha256)}</dd>
          </div>
          <div>
            <dt>Estado de auditoría</dt>
            <dd>{audit.status}</dd>
          </div>
          <div>
            <dt>Última verificación</dt>
            <dd>{formatDateTime(audit.checked_at)}</dd>
          </div>
        </dl>
      </section>

      <ReportLinks reports={reports} />

      <aside className={styles.notice}>
        <strong>La interfaz no genera ni altera reportes, hallazgos, hashes o veredictos.</strong>
        <span>La descarga sólo presenta el artefacto que el backend asoció al resultado actual.</span>
      </aside>
    </div>
  );
}
