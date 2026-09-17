import type { Metadata } from "next";

import styles from "./page.module.css";

export const metadata: Metadata = {
  title: "Acerca de",
  description: "Qué es ZAYNOR, para qué sirve y cómo se ubica junto a la telemetría en vivo.",
};

const githubUrl = "https://github.com/annatchijova/zaynor";

export default function AboutPage() {
  return (
    <div className={styles.workspace}>
      <header className={styles.header}>
        <p className={styles.eyebrow}>Qué es ZAYNOR</p>
        <h1>Investigación forense postmortem, local y determinista.</h1>
        <p>
          ZAYNOR recibe un incidente ya declarado y evidencia ya recolectada. Un motor
          matemático determinista analiza esa evidencia y sella un veredicto. Un modelo de
          lenguaje local, corriendo en Ollama, explica ese veredicto — nunca lo decide.
        </p>
        <a className={styles.githubLink} href={githubUrl} rel="noopener noreferrer" target="_blank">
          Ver el repositorio en GitHub
          <span aria-hidden="true"> ↗</span>
        </a>
      </header>

      <section aria-labelledby="hybrid-title" className={styles.section}>
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>Arquitectura híbrida</p>
          <h2 id="hybrid-title">Dos mitades, dos momentos del incidente</h2>
        </div>
        <div className={styles.hybridGrid}>
          <article className={styles.hybridCard}>
            <p className={styles.hybridLabel}>En vivo</p>
            <h3>Telemetría con Velociraptor</h3>
            <p>
              Recolección y monitoreo en tiempo real sobre los endpoints, mientras el incidente
              todavía puede estar en curso. Es la otra mitad del producto, construida por otro
              integrante del equipo.
            </p>
          </article>
          <article className={`${styles.hybridCard} ${styles.hybridCardActive}`}>
            <p className={styles.hybridLabel}>Postmortem — esto es ZAYNOR</p>
            <h3>Reconstrucción determinista después del hecho</h3>
            <p>
              Empieza donde termina la recolección: evidencia ya congelada, un caso ya declarado.
              No monitorea nada en tiempo real y no reemplaza un SIEM ni un EDR — reconstruye qué
              sostiene la evidencia, qué no se puede saber todavía, y sella esa respuesta.
            </p>
          </article>
        </div>
      </section>

      <section aria-labelledby="audiences-title" className={styles.section}>
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>Dos formas de llegar al mismo resultado sellado</p>
          <h2 id="audiences-title">Terminal para verificar, asistencia para preguntar</h2>
        </div>
        <div className={styles.branchGrid}>
          <article className={styles.seniorBranch}>
            <h3>CLI</h3>
            <p>
              <code>zaynor freeze</code> → <code>zaynor analyze</code> → <code>zaynor audit</code>.
              Acceso directo al resultado sellado, sin narración de por medio, para quien quiere
              verificar cada hash con sus propias manos.
            </p>
          </article>
          <article className={styles.juniorBranch}>
            <h3>Asistencia — chat</h3>
            <p>
              Le pregunta al caso en lenguaje natural. La respuesta se narra a partir del
              resultado ya sellado, con cada afirmación verificada contra ese resultado antes de
              mostrarse — lo que no se puede sostener, se marca y se retira. No es una consola
              &ldquo;para juniors&rdquo;: senior o junior la usan según la pregunta, no según el rol.
            </p>
          </article>
        </div>
      </section>

      <section aria-labelledby="guarantees-title" className={styles.section}>
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>Garantías, no promesas</p>
          <h2 id="guarantees-title">Determinista y local, verificable en ambos sentidos</h2>
        </div>
        <div className={styles.guaranteeGrid}>
          <div className={styles.guaranteeCard}>
            <p className={styles.guaranteeLabel}>Determinista</p>
            <p>
              El motor matemático produce y sella el resultado antes de que cualquier modelo de
              lenguaje intervenga. El mismo caso, analizado dos veces, produce el mismo hash.
            </p>
          </div>
          <div className={styles.guaranteeCard}>
            <p className={styles.guaranteeLabel}>Local</p>
            <p>
              La narración corre sobre Ollama en la propia máquina. Ningún dato del caso sale a un
              LLM de terceros — no hay llamada a una nube que se pueda auditar desde afuera porque
              no existe.
            </p>
          </div>
          <div className={styles.guaranteeCard}>
            <p className={styles.guaranteeLabel}>Exportable</p>
            <p>
              Cada resultado sellado se puede exportar como reporte en Markdown, HTML o PDF,
              siempre con el mismo hash de resultado impreso para volver a verificarlo de forma
              independiente.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
