import type { AuditStatus, CaseOverview } from "@/lib/api/contracts";
import { formatDateTime, formatHash } from "@/lib/presentation/formatters";

import { IntegrityBadge } from "../ui/integrity-badge";
import { SectionCard } from "../ui/section-card";
import { CaseNavigation } from "./case-navigation";

import styles from "./case-workspace.module.css";

interface AuditSummaryProps {
  readonly audit: AuditStatus;
  readonly caseId: string;
  readonly result: CaseOverview["authoritative_result"];
  readonly seal: CaseOverview["seal"];
  readonly snapshot: CaseOverview["snapshot"];
}

const auditLabels: ReadonlyArray<readonly [keyof Pick<AuditStatus, "manifest" | "snapshot" | "evidence" | "result" | "seal">, string]> = [
  ["manifest", "Manifest"],
  ["snapshot", "Snapshot"],
  ["evidence", "Evidencia"],
  ["result", "Resultado"],
  ["seal", "Sello"],
];

export function AuditSummary({ audit, caseId, result, seal, snapshot }: AuditSummaryProps) {
  return (
    <div className={styles.workspace}>
      <header className={styles.caseHeader}>
        <div>
          <p className={styles.eyebrow}>Cadena de auditoría</p>
          <h1>{caseId}</h1>
          <p>Verificación de los elementos que componen el resultado sellado.</p>
        </div>
        <IntegrityBadge label="Auditoría global" status={audit.status} />
      </header>

      <CaseNavigation activeView="audit" caseId={caseId} />

      <section aria-labelledby="audit-status-title" className={styles.section}>
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>Estado</p>
          <h2 id="audit-status-title">{audit.detail ?? "Cadena de integridad verificada"}</h2>
          <p>El bundle no trae una nota narrativa adicional: el estado se obtiene verificando manifest, snapshot, evidencia, resultado y sello.</p>
        </div>
        <div className={styles.auditGrid}>
          {auditLabels.map(([key, label]) => (
            <SectionCard key={key}>
              <IntegrityBadge label={label} status={audit[key]} />
            </SectionCard>
          ))}
        </div>
      </section>

      <section className={styles.analysisGrid}>
        <SectionCard>
          <p className={styles.eyebrow}>Hashes verificados</p>
          <dl className={styles.factList}>
            <div>
              <dt>Manifest</dt>
              <dd className={styles.hash}>{formatHash(snapshot.manifest_sha256)}</dd>
            </div>
            <div>
              <dt>Resultado</dt>
              <dd className={styles.hash}>{formatHash(result.result_sha256)}</dd>
            </div>
            <div>
              <dt>Sello</dt>
              <dd className={styles.hash}>{formatHash(seal.result_sha256)}</dd>
            </div>
          </dl>
        </SectionCard>
        <SectionCard>
          <p className={styles.eyebrow}>Registro</p>
          <dl className={styles.factList}>
            <div>
              <dt>Comprobado</dt>
              <dd>{formatDateTime(audit.checked_at)}</dd>
            </div>
            <div>
              <dt>Provenance</dt>
              <dd>{audit.provenance}</dd>
            </div>
            <div>
              <dt>Referencias</dt>
              <dd>{result.audit_refs.join(", ")}</dd>
            </div>
          </dl>
        </SectionCard>
      </section>
    </div>
  );
}
