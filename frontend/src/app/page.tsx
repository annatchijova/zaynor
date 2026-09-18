import Image from "next/image";
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
          <div className={styles.heroOrb} aria-hidden="true">
            <Image alt="" height={72} src="/brand/logo-zaynor.svg" width={84} />
          </div>
          <div className={styles.heroStack}>
            <span><b>01</b> postmortem · bundle sellado</span>
            <span><b>02</b> live lab · Velociraptor / OTel</span>
            <span><b>03</b> freeze → VIGÍA → sello</span>
          </div>
          <Link className={styles.primaryAction} href="/cases">Explorar catálogo de casos →</Link>
        </div>
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
            <strong className={styles.systemValue}>OLLAMA · {health.ollama}</strong>
          </SectionCard>
        </div>
      </section>

      <section aria-labelledby="modes-title" className={styles.modes}>
        <div className={styles.sectionHeading}>
          <p className={styles.kicker}>Dos modos, una frontera de autoridad</p>
          <h2 id="modes-title">Postmortem y LIVE lab</h2>
        </div>
        <div className={styles.modeGrid}>
          <article className={styles.modeCard}>
            <span className={styles.modeTag}>POSTMORTEM</span>
            <h3>Bundles ya adquiridos</h3>
            <p>Casos públicos y fixtures sellados: evidencia congelada, VIGÍA determinista, resultado y reportes verificables.</p>
          </article>
          <article className={styles.modeCard}>
            <span className={styles.modeTag}>LIVE LAB</span>
            <h3>Adquisición local acotada</h3>
            <p>Velociraptor y observabilidad local producen evidencia y provenance. Después del freeze, sólo el motor puede emitir el veredicto.</p>
          </article>
        </div>
        <p className={styles.modeNote}>La demo pública reproduce bundles. La demo local conecta ZAYNOR API → Ollama; OpenWebUI usa el endpoint OpenAI-compatible y MCP queda para investigación/capacidades permitidas.</p>
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

      <section aria-labelledby="public-resources-title" className={styles.resources}>
        <div className={styles.sectionHeading}>
          <p className={styles.kicker}>Documentación pública · al final del recorrido</p>
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
          <a className={styles.resourceCard} href="https://annatchijova.github.io/zaynor/pitch.html" rel="noopener noreferrer" target="_blank">
            <span className={styles.resourceIcon}>▣</span>
            <strong>Slides de ZAYNOR</strong>
            <span>Presentación visual del problema, la arquitectura y la frontera de autoridad.</span>
          </a>
        </div>
        <p className={styles.resourceNote}>Los enlaces públicos abren documentación en una pestaña nueva y no transmiten datos del caso.</p>
      </section>
    </div>
  );
}
