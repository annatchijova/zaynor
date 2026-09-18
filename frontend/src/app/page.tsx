import Link from "next/link";

import { SectionCard } from "@/components/ui/section-card";
import { api } from "@/lib/api";

import styles from "./page.module.css";

export default async function OverviewPage() {
  const [health, cases] = await Promise.all([api.getHealth(), api.listCases()]);
  const featuredCase = cases.find((item) => item.case_id === "VIGIA-NITROBA-M57-001") ?? cases[0];

  return (
    <div className={styles.page}>
      <header className={styles.intro}>
        <div>
          <p className={styles.kicker}>ZAYNOR · LOCAL FORENSIC INTELLIGENCE</p>
          <h1>La evidencia habla. El veredicto queda sellado.</h1>
          <p className={styles.lede}>
            Investigación postmortem con casos reales, bundles verificables y asistencia local.
            El motor matemático decide; la IA ayuda a entender.
          </p>
        </div>
        <div className={styles.heroAside}>
          <div className={styles.heroOrb} aria-hidden="true"><span /></div>
          <div className={styles.heroStack}>
            <span><b>01</b> evidencia congelada</span>
            <span><b>02</b> VIGÍA determinista</span>
            <span><b>03</b> sello verificado</span>
          </div>
          <Link className={styles.primaryAction} href="/cases">Explorar catálogo de casos →</Link>
        </div>
      </header>

      <section aria-labelledby="public-resources-title" className={styles.resources}>
        <div className={styles.sectionHeading}>
          <p className={styles.kicker}>Demo en vivo · documentación pública</p>
          <h2 id="public-resources-title">Resultados, reportes y arquitectura</h2>
        </div>
        <div className={styles.resourceGrid}>
          {featuredCase ? (
            <Link className={styles.resourceCard} href={`/cases/${featuredCase.case_id}/reports`}>
              <span className={styles.resourceIcon}>↗</span>
              <strong>Descargar MD · HTML · PDF</strong>
              <span>Reportes sellados de {featuredCase.case_id}. El backend genera los artefactos; la UI no altera su contenido.</span>
            </Link>
          ) : null}
          <a className={styles.resourceCard} href="https://annatchijova.github.io/zaynor/architecture.html" rel="noopener noreferrer" target="_blank">
            <span className={styles.resourceIcon}>◎</span>
            <strong>Diagramas publicados de ZAYNOR</strong>
            <span>Arquitectura de autoridad y flujo de evidencia en una pestaña nueva.</span>
          </a>
          <a className={styles.resourceCard} href="https://annatchijova.github.io/vigia/vigia_diagrams.html" rel="noopener noreferrer" target="_blank">
            <span className={styles.resourceIcon}>◌</span>
            <strong>Diagramas publicados de VIGÍA</strong>
            <span>Referencias visuales del motor y sus capacidades, sin transmitir datos del caso.</span>
          </a>
        </div>
        <p className={styles.resourceNote}>Los enlaces públicos abren documentación en una pestaña nueva y no transmiten datos del caso.</p>
      </section>

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
            <strong className={styles.systemValue}>OLLAMA · {health.ollama}</strong>
          </SectionCard>
        </div>
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
