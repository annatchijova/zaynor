import type { Metadata } from "next";

import styles from "./page.module.css";

export const metadata: Metadata = {
  title: "Arquitectura",
  description: "Límites de autoridad y flujo forense de ZAYNOR.",
};

const vigiaDiagramUrl = "https://annatchijova.github.io/vigia/vigia_diagrams.html";
const zaynorDiagramUrl = "https://annatchijova.github.io/zaynor/architecture.html";

export default function ArchitecturePage() {
  return (
    <div className={styles.workspace}>
      <header className={styles.header}>
        <p className={styles.eyebrow}>Arquitectura de autoridad</p>
        <h1>La evidencia y el motor determinista conservan la decisión</h1>
        <p>
          ZAYNOR comienza después de que un incidente fue declarado y su evidencia fue recolectada.
          La interfaz explica el resultado; no participa de la decisión forense.
        </p>
      </header>

      <section aria-labelledby="authority-path-title" className={styles.section}>
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>Camino autoritativo</p>
          <h2 id="authority-path-title">De evidencia congelada a resultado sellado</h2>
        </div>
        <figure className={styles.flowFigure}>
          <ol className={styles.authorityFlow}>
            <li>
              <strong>Incidente declarado</strong>
              <span>Entrada externa: incidente y evidencia ya recolectada.</span>
            </li>
            <li>
              <strong>Freeze del caso</strong>
              <span>Manifest, SHA-256 y case_id inmutable.</span>
            </li>
            <li>
              <strong>VIGÍA determinista</strong>
              <span>Análisis forense reproducible sobre el snapshot.</span>
            </li>
            <li>
              <strong>Resultado autoritativo</strong>
              <span>Findings, unknowns y veredicto emitidos por el motor.</span>
            </li>
            <li>
              <strong>Sello y auditoría</strong>
              <span>Integridad vinculada a resultado y evidencia.</span>
            </li>
          </ol>
          <figcaption>
            Sólo una nueva pasada determinista sobre evidencia incorporada puede producir un resultado autoritativo nuevo.
          </figcaption>
        </figure>
      </section>

      <section aria-labelledby="narration-path-title" className={styles.section}>
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>Frontera de narración e investigación</p>
          <h2 id="narration-path-title">La IA explica y propone; no decide</h2>
        </div>
        <div className={styles.branchGrid}>
          <article className={styles.narrationBranch}>
            <h3>Narración local</h3>
            <ol>
              <li>Consume sólo el paquete autoritativo sellado.</li>
              <li>Explica para distintos perfiles analistas.</li>
              <li>Produce reportes como proyección del resultado existente.</li>
            </ol>
          </article>
          <article className={styles.investigationBranch}>
            <h3>Investigación acotada</h3>
            <ol>
              <li>El modelo propone una pregunta read-only.</li>
              <li>Policy y capability gate deciden si puede ejecutarse.</li>
              <li>La observación no es un finding ni un veredicto.</li>
              <li>La nueva evidencia debe volver a VIGÍA para reanálisis.</li>
            </ol>
          </article>
        </div>
        <aside className={styles.boundaryNotice}>
          <strong>LLM ≠ authority · observation ≠ verdict · proposal ≠ finding</strong>
          <span>La narración nunca escribe en el camino autoritativo.</span>
        </aside>
      </section>

      <section aria-labelledby="diagrams-title" className={styles.section}>
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>Diagramas publicados</p>
          <h2 id="diagrams-title">Referencias visuales</h2>
        </div>
        <div className={styles.links}>
          <a href={zaynorDiagramUrl} rel="noopener noreferrer" target="_blank">
            Abrir diagrama publicado de ZAYNOR
          </a>
          <a href={vigiaDiagramUrl} rel="noopener noreferrer" target="_blank">
            Abrir diagramas publicados de VIGÍA
          </a>
        </div>
        <p className={styles.externalNote}>
          Los enlaces abren documentación pública en una pestaña nueva y no transmiten datos del caso.
        </p>
      </section>
    </div>
  );
}
