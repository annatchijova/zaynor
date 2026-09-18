import Link from "next/link";

import { IntegrityBadge } from "@/components/ui/integrity-badge";
import { VerdictPill } from "@/components/ui/verdict-pill";
import { getFrameworkCaseData } from "@/components/case/framework-indicators";
import { api } from "@/lib/api";
import { demoCaseMeta } from "@/lib/api/fixtures";

import styles from "./page.module.css";

type CaseKind = "adversarial" | "benign" | "break" | "real" | "corpus";

function kindForCase(caseId: string): CaseKind {
  if (caseId.includes("BREAK")) return "break";
  if (caseId.includes("FP-") || caseId.startsWith("FP-")) return "benign";
  if (caseId.includes("FN-")) return "adversarial";
  if (caseId.includes("REAL") || caseId.includes("NITROBA")) return "real";
  if (caseId.startsWith("case_")) return "adversarial";
  return "corpus";
}

const kindLabels: Record<CaseKind, string> = {
  adversarial: "Adversarial",
  benign: "Benigno / falso positivo",
  break: "Break test",
  real: "Incidente real / público",
  corpus: "Corpus VIGÍA",
};

export default async function CasesPage() {
  const cases = await api.listCases();

  return (
    <div className={styles.page}>
      <header className={styles.hero}>
        <div>
          <p className={styles.kicker}>ZAYNOR · CATÁLOGO DE CASOS</p>
          <h1>Elegí un caso. Abrilo. Seguí la evidencia.</h1>
          <p className={styles.lede}>
            Casos del corpus y bundles reproducibles de VIGÍA. Cada tarjeta conserva el resultado
            autoritativo del fixture y separa contexto MITRE/NIST de la autoridad matemática.
          </p>
        </div>
        <div className={styles.heroBadge}>
          <strong>{cases.length}</strong>
          <span>casos disponibles</span>
        </div>
      </header>

      <section aria-label="Catálogo de casos" className={styles.catalog}>
        {cases.map((caseSummary) => {
          const kind = kindForCase(caseSummary.case_id);
          const metadata = demoCaseMeta[caseSummary.case_id];
          const framework = getFrameworkCaseData(caseSummary.case_id);

          return (
            <article className={styles.caseCard} data-kind={kind} key={caseSummary.case_id}>
              <div className={styles.cardTopline}>
                <span className={styles.kind}>{kindLabels[kind]}</span>
                <span className={styles.caseId}>{caseSummary.case_id}</span>
              </div>
              <div className={styles.cardHeading}>
                <div>
                  <h2>{caseSummary.name ?? caseSummary.case_id}</h2>
                  <p>{metadata?.description ?? "Caso disponible en la fuente configurada."}</p>
                </div>
                <div className={styles.statuses}>
                  <VerdictPill verdict={caseSummary.verdict} />
                  <IntegrityBadge label="Sello" status={caseSummary.seal_status} />
                </div>
              </div>

              <div className={styles.cardFacts}>
                <span>
                  <b>MITRE</b>
                  {framework?.techniques.length
                    ? `${framework.techniques.length} técnica${framework.techniques.length === 1 ? "" : "s"}`
                    : "sin TTP explícito en el fixture"}
                </span>
                <span><b>NIST</b> contexto de respuesta</span>
              </div>

              <details className={styles.details}>
                <summary>Ver descripción e indicadores</summary>
                <div className={styles.detailsBody}>
                  <p>{metadata?.description ?? "Este caso no tiene una descripción adicional en el catálogo local."}</p>
                  {framework ? (
                    <div className={styles.techniques}>
                      {framework.techniques.length ? framework.techniques.map((technique) => (
                        <a
                          href={`https://attack.mitre.org/techniques/${technique.id.replace(".", "/")}`}
                          key={technique.id}
                          rel="noreferrer"
                          target="_blank"
                        >
                          <strong>{technique.id}</strong>
                          <span>{technique.name}</span>
                        </a>
                      )) : <span className={styles.noTechnique}>Sin TTP MITRE explícito declarado para este caso.</span>}
                    </div>
                  ) : (
                    <p className={styles.noTechnique}>MITRE contextual pendiente de correlación en este fixture; no se inventa una técnica.</p>
                  )}
                  <p className={styles.nistNote}><b>NIST:</b> detectar y analizar · contener · erradicar y recuperar · actividad post-incidente.</p>
                </div>
              </details>

              <div className={styles.cardActions}>
                <Link className={styles.openCase} href={`/cases/${caseSummary.case_id}`}>
                  Abrir caso →
                </Link>
                {caseSummary.case_id === "VIGIA-NITROBA-M57-001" ? (
                  <Link className={styles.reportLink} href={`/cases/${caseSummary.case_id}/reports`}>
                    Informes MD · HTML · PDF
                  </Link>
                ) : null}
              </div>
            </article>
          );
        })}
      </section>
    </div>
  );
}
