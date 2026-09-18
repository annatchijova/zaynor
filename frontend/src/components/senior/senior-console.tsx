import type { CaseOverview, EvidenceArtifact, Finding, JsonValue } from "@/lib/api";
import { formatDateTime, formatEngineDisplay, formatEvidenceRefs, formatHash } from "@/lib/presentation/formatters";

import { CaseNavigation } from "@/components/case/case-navigation";
import { FrameworkIndicators } from "@/components/case/framework-indicators";
import { FindingStateBadge } from "@/components/case/finding-state-badge";
import { InvestigationTimeline } from "@/components/investigation/investigation-timeline";
import { IntegrityBadge } from "@/components/ui/integrity-badge";
import { VerdictPill } from "@/components/ui/verdict-pill";

import styles from "./senior-console.module.css";

interface SeniorConsoleProps {
  readonly caseOverview: CaseOverview;
  readonly evidence: readonly EvidenceArtifact[];
}

function renderAnnotation(annotation: Readonly<Record<string, JsonValue>> | null): string {
  if (!annotation) {
    return "No suministrada";
  }

  return Object.entries(annotation)
    .map(([key, value]) => `${key}: ${String(value)}`)
    .join(" · ");
}

function FindingRow({ finding }: { readonly finding: Finding }) {
  return (
    <tr>
      <th scope="row">{finding.finding_id}</th>
      <td><FindingStateBadge state={finding.state} /></td>
      <td>{finding.rationale}</td>
      <td>{formatEvidenceRefs(finding.evidence_refs)}</td>
      <td>{finding.lineage_ids.join(", ")}</td>
      <td>{renderAnnotation(finding.mitre)}</td>
      <td>{renderAnnotation(finding.nist)}</td>
    </tr>
  );
}

export function SeniorConsole({ caseOverview, evidence }: SeniorConsoleProps) {
  const { audit, authoritative_result: result, case_id: caseId, investigation, seal, snapshot } = caseOverview;

  return (
    <div className={styles.workspace}>
      <header className={styles.header}>
        <div>
          <p className={styles.eyebrow}>Consola senior</p>
          <h1>{caseId}</h1>
          <p>Detalle técnico suministrado por los contratos autoritativos, sin narración ni inferencia adicional.</p>
        </div>
        <div className={styles.headerStatus}>
          <VerdictPill verdict={result.verdict} />
          <IntegrityBadge label="Sello" status={seal.status} />
        </div>
      </header>

      <CaseNavigation activeView="senior" caseId={caseId} />

      <section aria-labelledby="authority-state-title" className={styles.authorityState}>
        <div>
          <p className={styles.eyebrow}>Estado autoritativo actual</p>
          <h2 id="authority-state-title">Resultado {result.verdict}</h2>
        </div>
        <dl>
          <div>
            <dt>Result SHA-256</dt>
            <dd>{formatHash(result.result_sha256)}</dd>
          </div>
          <div>
            <dt>Engine</dt>
            <dd>{formatEngineDisplay(result.engine)}</dd>
          </div>
          <div>
            <dt>Configuration hash</dt>
            <dd>{formatHash(result.engine.configuration_hash)}</dd>
          </div>
          <div>
            <dt>Audit refs</dt>
            <dd>{result.audit_refs.join(", ")}</dd>
          </div>
        </dl>
      </section>

      <section aria-labelledby="findings-title" className={styles.section}>
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>Findings y evidencia discriminante</p>
          <h2 id="findings-title">Matriz técnica de resultados</h2>
        </div>
        <div className={styles.tableWrapper}>
          <table>
            <caption>Hallazgos autoritativos y las referencias que los sostienen o limitan.</caption>
            <thead>
              <tr>
                <th scope="col">ID</th>
                <th scope="col">Estado</th>
                <th scope="col">Rationale</th>
                <th scope="col">Evidencia</th>
                <th scope="col">Linajes</th>
                <th scope="col">MITRE</th>
                <th scope="col">NIST</th>
              </tr>
            </thead>
            <tbody>{result.findings.map((finding) => <FindingRow finding={finding} key={finding.finding_id} />)}</tbody>
          </table>
        </div>
      </section>

      <FrameworkIndicators caseId={caseId} />

      <section className={styles.twoColumn}>
        <article>
          <p className={styles.eyebrow}>Señales y scores</p>
          <h2>Señales deterministas</h2>
          <ul className={styles.recordList}>
            {result.signals.map((signal) => (
              <li key={signal.signal_id}>
                <strong>{signal.signal_id}</strong>
                <span>{signal.source}</span>
                <span>Artifact: {signal.artifact ?? "No suministrado"}</span>
                <span>Score: {signal.score ?? "No suministrado"}</span>
                <span>Confidence: {signal.confidence ?? "No suministrada"}</span>
              </li>
            ))}
          </ul>
        </article>
        <article>
          <p className={styles.eyebrow}>Fracturas e hipótesis</p>
          <h2>Límites y alternativas</h2>
          <ul className={styles.recordList}>
            {result.fractures.map((fracture) => (
              <li key={fracture.fracture_id}>
                <strong>{fracture.fracture_id} · {fracture.type}</strong>
                <span>{fracture.description}</span>
                <span>Severidad: {fracture.severity ?? "No suministrada"}</span>
                <span>{formatEvidenceRefs(fracture.evidence_refs)}</span>
              </li>
            ))}
            {result.hypotheses.map((hypothesis) => (
              <li key={hypothesis.hypothesis_id}>
                <strong>{hypothesis.hypothesis_id} · {hypothesis.status}</strong>
                <span>{hypothesis.statement}</span>
                <span>{hypothesis.rationale ?? "Sin justificación suministrada"}</span>
              </li>
            ))}
          </ul>
        </article>
      </section>

      <section aria-labelledby="provenance-title" className={styles.section}>
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>Provenance y linaje</p>
          <h2 id="provenance-title">Artefactos incluidos en el snapshot</h2>
        </div>
        <div className={styles.tableWrapper}>
          <table>
            <caption>Provenance declarada para los artefactos incluidos en el conjunto congelado.</caption>
            <thead>
              <tr>
                <th scope="col">Artefacto</th>
                <th scope="col">Linaje</th>
                <th scope="col">Origen</th>
                <th scope="col">Estado</th>
                <th scope="col">Provenance</th>
              </tr>
            </thead>
            <tbody>
              {evidence.map((artifact) => (
                <tr key={artifact.evidence_id}>
                  <th scope="row">{artifact.evidence_id}</th>
                  <td>{artifact.lineage_id}</td>
                  <td>{artifact.source}</td>
                  <td>{artifact.manifest_status}</td>
                  <td>{artifact.provenance.map((entry) => `${entry.label}: ${entry.value} (${entry.status})`).join(" · ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className={styles.twoColumn}>
        <article>
          <p className={styles.eyebrow}>Audit chain</p>
          <h2>Cadena de verificación</h2>
          <dl className={styles.definitionList}>
            <div><dt>Manifest</dt><dd>{audit.manifest}</dd></div>
            <div><dt>Snapshot</dt><dd>{audit.snapshot}</dd></div>
            <div><dt>Evidence</dt><dd>{audit.evidence}</dd></div>
            <div><dt>Result</dt><dd>{audit.result}</dd></div>
            <div><dt>Seal</dt><dd>{audit.seal}</dd></div>
            <div><dt>Checked</dt><dd>{formatDateTime(audit.checked_at)}</dd></div>
          </dl>
        </article>
        <article>
          <p className={styles.eyebrow}>MCP calls y versiones</p>
          <h2>Datos no suministrados</h2>
          <p className={styles.emptyData}>El contrato actual no suministra llamadas MCP ni hashes de resultados anteriores.</p>
          <dl className={styles.definitionList}>
            <div><dt>Versión actual</dt><dd>{formatHash(result.result_sha256)}</dd></div>
            <div><dt>Evidence set</dt><dd>{formatHash(snapshot.evidence_set_sha256)}</dd></div>
            <div><dt>Canonicalization</dt><dd>{seal.canonicalize_version}</dd></div>
          </dl>
        </article>
      </section>

      <section aria-labelledby="proposal-history-title" className={styles.section}>
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>Proposal history</p>
          <h2 id="proposal-history-title">Investigación no autoritativa</h2>
        </div>
        <InvestigationTimeline investigation={investigation} />
      </section>
    </div>
  );
}
