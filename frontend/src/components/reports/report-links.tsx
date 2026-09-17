import type { ReportArtifact } from "@/lib/api";

import { isSafeReportUrl } from "./report-url";

import styles from "./report-links.module.css";

interface ReportLinksProps {
  readonly reports: readonly ReportArtifact[];
}

function ReportAction({
  artifact,
  download,
  label,
}: {
  readonly artifact: ReportArtifact;
  readonly download?: boolean;
  readonly label: string;
}) {
  if (!isSafeReportUrl(artifact.download_url)) {
    return (
      <span aria-disabled="true" className={styles.unavailable}>
        {label} no disponible en modo demo
      </span>
    );
  }

  return (
    <a
      className={styles.action}
      download={download ? true : undefined}
      href={artifact.download_url}
      rel="noopener noreferrer"
      target={download ? undefined : "_blank"}
    >
      {label}
    </a>
  );
}

export function ReportLinks({ reports }: ReportLinksProps) {
  const markdown = reports.find((report) => report.format === "md");
  const html = reports.find((report) => report.format === "html");
  const pdf = reports.find((report) => report.format === "pdf");

  return (
    <section aria-labelledby="report-artifacts-title" className={styles.reports}>
      <div className={styles.heading}>
        <div>
          <p className={styles.eyebrow}>Artefactos de backend</p>
          <h2 id="report-artifacts-title">Abrir o descargar el reporte sellado</h2>
        </div>
        <p>Los enlaces apuntan a artefactos producidos por el backend. Esta interfaz no genera su contenido.</p>
      </div>

      <div className={styles.grid}>
        <article>
          <h3>Markdown</h3>
          <p>Texto auditable para revisión y custodia.</p>
          <div className={styles.actions}>
            {markdown ? <ReportAction artifact={markdown} label="Ver Markdown" /> : null}
            {markdown ? <ReportAction artifact={markdown} download label="Descargar Markdown" /> : null}
          </div>
          <code>{markdown?.content_type ?? "No suministrado"}</code>
        </article>
        <article>
          <h3>HTML</h3>
          <p>Vista de reporte generada fuera del navegador.</p>
          <div className={styles.actions}>
            {html ? <ReportAction artifact={html} label="Exportar HTML" /> : null}
          </div>
          <code>{html?.content_type ?? "No suministrado"}</code>
        </article>
        <article>
          <h3>PDF</h3>
          <p>Documento portable generado por el backend.</p>
          <div className={styles.actions}>
            {pdf ? <ReportAction artifact={pdf} download label="Exportar PDF" /> : null}
          </div>
          <code>{pdf?.content_type ?? "No suministrado"}</code>
        </article>
      </div>
    </section>
  );
}
