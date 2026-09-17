import Link from "next/link";

import { IntegrityBadge } from "@/components/ui/integrity-badge";
import { SectionCard } from "@/components/ui/section-card";
import { VerdictPill } from "@/components/ui/verdict-pill";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/presentation/formatters";

import styles from "./page.module.css";

export default async function OverviewPage() {
  const [health, cases] = await Promise.all([api.getHealth(), api.listCases()]);

  return (
    <div className={styles.page}>
      <header className={styles.intro}>
        <div>
          <p className={styles.kicker}>Postmortem DFIR</p>
          <h1>Consola de análisis forense.</h1>
          <p className={styles.lede}>
            Resultados deterministas, evidencia congelada y una frontera explícita entre
            investigación asistida y autoridad forense.
          </p>
        </div>
        {cases[0] ? (
          <Link className={styles.primaryAction} href={`/cases/${cases[0].case_id}`}>
            Abrir caso
          </Link>
        ) : null}
      </header>

      <section aria-labelledby="system-title" className={styles.foundation}>
        <div className={styles.sectionHeading}>
          <p className={styles.kicker}>Sistema local</p>
          <h2 id="system-title">Estado operativo</h2>
        </div>
        <div className={styles.foundationGrid}>
          <SectionCard>
            <p className={styles.cardLabel}>Servicio</p>
            <strong className={styles.systemValue}>{health.status}</strong>
          </SectionCard>
          <SectionCard>
            <p className={styles.cardLabel}>Motor determinista</p>
            <strong className={styles.systemValue}>{health.engine}</strong>
          </SectionCard>
          <SectionCard>
            <p className={styles.cardLabel}>Narración local</p>
            <strong className={styles.systemValue}>{health.ollama}</strong>
          </SectionCard>
        </div>
      </section>

      <section aria-labelledby="cases-title" className={styles.casesSection}>
        <div className={styles.sectionHeading}>
          <p className={styles.kicker}>Casos recientes</p>
          <h2 id="cases-title">Resultados disponibles</h2>
        </div>
        {cases.length ? (
          <ul className={styles.caseList}>
            {cases.map((caseSummary) => (
              <li key={caseSummary.case_id}>
                <Link href={`/cases/${caseSummary.case_id}`}>
                  <div>
                    <span className={styles.caseId}>{caseSummary.case_id}</span>
                    <span className={styles.caseTime}>
                      Actualizado: {formatDateTime(caseSummary.updated_at)}
                    </span>
                  </div>
                  <div className={styles.caseSignals}>
                    <VerdictPill verdict={caseSummary.verdict} />
                    <IntegrityBadge label="Sello" status={caseSummary.seal_status} />
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        ) : (
          <SectionCard>
            <p>No hay casos disponibles en la fuente configurada.</p>
          </SectionCard>
        )}
      </section>

      <section aria-labelledby="boundary-title" className={styles.boundary}>
        <div>
          <p className={styles.kicker}>Frontera de autoridad</p>
          <h2 id="boundary-title">La narración no modifica el veredicto.</h2>
        </div>
        <ol className={styles.boundarySteps}>
          <li>La evidencia se congela y el motor determinista analiza el caso.</li>
          <li>El resultado se sella y queda disponible para auditoría.</li>
          <li>La IA sólo puede explicar o proponer consultas read-only.</li>
        </ol>
      </section>
    </div>
  );
}
