import Link from "next/link";

import type { CaseOverview } from "@/lib/api/contracts";
import { formatConfidence, formatDateTime, formatEvidenceRefs, formatHash } from "@/lib/presentation/formatters";

import { IntegrityBadge } from "../ui/integrity-badge";
import { SectionCard } from "../ui/section-card";
import { VerdictPill } from "../ui/verdict-pill";
import { CaseNavigation } from "./case-navigation";
import { FindingStateBadge } from "./finding-state-badge";

import styles from "./case-workspace.module.css";

interface CaseOverviewProps {
  readonly caseOverview: CaseOverview;
}

export function CaseOverviewView({ caseOverview }: CaseOverviewProps) {
  const { authoritative_result: result, audit, case_id: caseId, seal, snapshot } = caseOverview;

  return (
    <div className={styles.workspace}>
      <header className={styles.caseHeader}>
        <div>
          <p className={styles.eyebrow}>Caso congelado</p>
          <h1>{caseId}</h1>
          <p>Resultado autoritativo emitido por el motor determinista.</p>
        </div>
        <div className={styles.headerActions}>
          <VerdictPill verdict={result.verdict} />
          <Link className={styles.primaryAction} href={`/cases/${caseId}/evidence`}>
            Revisar evidencia
          </Link>
        </div>
      </header>

      <CaseNavigation activeView="overview" caseId={caseId} />

      <section aria-label="Cadena de custodia" className={styles.custodyBand}>
        <IntegrityBadge label="Snapshot" status={snapshot.status} />
        <IntegrityBadge label="Sello" status={seal.status} />
        <IntegrityBadge label="Auditoría" status={audit.status} />
        <span className={styles.custodyTimestamp}>Verificado: {formatDateTime(audit.checked_at)}</span>
      </section>

      <section aria-labelledby="result-title" className={styles.resultGrid}>
        <SectionCard className={styles.resultCard}>
          <p className={styles.eyebrow}>Resultado autoritativo</p>
          <h2 id="result-title">{result.verdict}</h2>
          <dl className={styles.factList}>
            <div>
              <dt>Confianza</dt>
              <dd>{formatConfidence(result.confidence)}</dd>
            </div>
            <div>
              <dt>Hash de resultado</dt>
              <dd className={styles.hash}>{formatHash(result.result_sha256)}</dd>
            </div>
            <div>
              <dt>Motor</dt>
              <dd>{result.engine.name}</dd>
            </div>
          </dl>
        </SectionCard>
        <SectionCard>
          <p className={styles.eyebrow}>Snapshot de evidencia</p>
          <dl className={styles.factList}>
            <div>
              <dt>Manifest</dt>
              <dd className={styles.hash}>{formatHash(snapshot.manifest_sha256)}</dd>
            </div>
            <div>
              <dt>Evidencias</dt>
              <dd>{snapshot.artifact_count}</dd>
            </div>
            <div>
              <dt>Hash del conjunto</dt>
              <dd className={styles.hash}>{formatHash(snapshot.evidence_set_sha256)}</dd>
            </div>
          </dl>
        </SectionCard>
      </section>

      <section aria-labelledby="findings-title" className={styles.section}>
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>Hallazgos</p>
          <h2 id="findings-title">Qué sostiene el resultado</h2>
        </div>
        <div className={styles.findingList}>
          {result.findings.map((finding) => (
            <article className={styles.finding} key={finding.finding_id}>
              <div className={styles.findingMeta}>
                <span>{finding.finding_id}</span>
                <FindingStateBadge state={finding.state} />
              </div>
              <p>{finding.rationale}</p>
              <span className={styles.referenceText}>
                {formatEvidenceRefs(finding.evidence_refs)}
              </span>
            </article>
          ))}
        </div>
      </section>

      <section className={styles.analysisGrid}>
        <SectionCard>
          <p className={styles.eyebrow}>Incertidumbres</p>
          <h2>Lo que no se sabe</h2>
          <ul className={styles.statementList}>
            {result.unknowns.map((unknown) => (
              <li key={unknown.id}>
                <strong>{unknown.statement}</strong>
                {unknown.what_would_resolve ? <span>{unknown.what_would_resolve}</span> : null}
              </li>
            ))}
          </ul>
        </SectionCard>
        <SectionCard>
          <p className={styles.eyebrow}>Hipótesis</p>
          <h2>Alternativas abiertas</h2>
          <ul className={styles.statementList}>
            {result.hypotheses.map((hypothesis) => (
              <li key={hypothesis.hypothesis_id}>
                <strong>{hypothesis.statement}</strong>
                {hypothesis.rationale ? <span>{hypothesis.rationale}</span> : null}
              </li>
            ))}
          </ul>
        </SectionCard>
      </section>

      <section aria-labelledby="fractures-title" className={styles.section}>
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>Fracturas</p>
          <h2 id="fractures-title">Límites del conjunto disponible</h2>
        </div>
        <div className={styles.fractureList}>
          {result.fractures.map((fracture) => (
            <article className={styles.fracture} key={fracture.fracture_id}>
              <span>{fracture.fracture_id}</span>
              <div>
                <strong>{fracture.type}</strong>
                <p>{fracture.description}</p>
              </div>
              <span className={styles.referenceText}>{formatEvidenceRefs(fracture.evidence_refs)}</span>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}
