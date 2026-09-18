"use client";

import { useRef, useState } from "react";

import type { EvidenceArtifact } from "@/lib/api/contracts";
import { formatFileSize, formatHash } from "@/lib/presentation/formatters";

import styles from "./evidence-table.module.css";

type DetailView = "findings" | "hash" | "metadata" | "provenance" | "request";

interface SelectedEvidence {
  readonly artifact: EvidenceArtifact;
  readonly view: DetailView;
}

interface EvidenceTableProps {
  readonly evidence: readonly EvidenceArtifact[];
}

const detailTitles: Record<DetailView, string> = {
  findings: "Hallazgos referenciados",
  hash: "Hash del artefacto",
  metadata: "Metadatos del artefacto",
  provenance: "Provenance",
  request: "Investigación read-only",
};

function EvidenceDetail({ selected }: { readonly selected: SelectedEvidence }) {
  const { artifact, view } = selected;

  if (view === "hash") {
    return <code className={styles.detailHash}>{artifact.sha256}</code>;
  }

  if (view === "metadata") {
    return Object.keys(artifact.metadata).length ? (
      <pre className={styles.detailCode}>{JSON.stringify(artifact.metadata, null, 2)}</pre>
    ) : (
      <p>El manifest no suministra metadatos adicionales para este artefacto.</p>
    );
  }

  if (view === "provenance") {
    return artifact.provenance.length ? (
      <dl className={styles.provenanceList}>
        {artifact.provenance.map((entry) => (
          <div key={`${entry.label}-${entry.value}`}>
            <dt>{entry.label}</dt>
            <dd>
              {entry.value} <span>{entry.status}</span>
            </dd>
          </div>
        ))}
      </dl>
    ) : (
      <p>Este artefacto no declara provenance adicional; su integridad está cubierta por el manifest congelado.</p>
    );
  }

  if (view === "findings") {
    return artifact.finding_refs.length ? (
      <ul className={styles.referenceList}>
        {artifact.finding_refs.map((reference) => (
          <li key={reference}>{reference}</li>
        ))}
      </ul>
    ) : (
      <p>Este artefacto no está referenciado por un hallazgo autoritativo.</p>
    );
  }

  return (
    <p>
      No hay una consulta read-only registrada para este artefacto. Una consulta futura sólo podría
      preparar una propuesta para una capacidad permitida; no modificaría el snapshot, la evidencia
      ni el veredicto autoritativo.
    </p>
  );
}

export function EvidenceTable({ evidence }: EvidenceTableProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const [selected, setSelected] = useState<SelectedEvidence | null>(null);

  function openDetail(artifact: EvidenceArtifact, view: DetailView) {
    setSelected({ artifact, view });
    dialogRef.current?.showModal();
  }

  return (
    <>
      <div className={styles.tableWrapper}>
        <table className={styles.table}>
          <caption>Evidencia preservada en el snapshot del caso.</caption>
          <thead>
            <tr>
              <th scope="col">Artefacto</th>
              <th scope="col">Integridad</th>
              <th scope="col">Referencias</th>
              <th scope="col">Acciones read-only</th>
            </tr>
          </thead>
          <tbody>
            {evidence.map((artifact) => (
              <tr key={artifact.evidence_id}>
                <th scope="row">
                  <strong>{artifact.evidence_id}</strong>
                  <span>{artifact.type}</span>
                  <span>{artifact.source}</span>
                </th>
                <td>
                  <span className={styles.integrityStatus}>{artifact.manifest_status}</span>
                  <code>{formatHash(artifact.sha256)}</code>
                  <span>{formatFileSize(artifact.size_bytes)}</span>
                </td>
                <td>{artifact.finding_refs.length ? artifact.finding_refs.join(", ") : "Sin referencias"}</td>
                <td>
                  <div className={styles.actions}>
                    <button onClick={() => openDetail(artifact, "metadata")} type="button">
                      Metadatos
                    </button>
                    <button onClick={() => openDetail(artifact, "hash")} type="button">
                      Hash
                    </button>
                    <button onClick={() => openDetail(artifact, "provenance")} type="button">
                      Provenance
                    </button>
                    <button onClick={() => openDetail(artifact, "findings")} type="button">
                      Hallazgos
                    </button>
                    <button onClick={() => openDetail(artifact, "request")} type="button">
                      Consulta read-only
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <dialog
        aria-labelledby="evidence-detail-title"
        className={styles.dialog}
        onClose={() => setSelected(null)}
        ref={dialogRef}
      >
        {selected ? (
          <div className={styles.dialogContent}>
            <p className={styles.dialogEyebrow}>{selected.artifact.evidence_id}</p>
            <h2 id="evidence-detail-title">{detailTitles[selected.view]}</h2>
            <EvidenceDetail selected={selected} />
            <form method="dialog">
              <button type="submit">Cerrar</button>
            </form>
          </div>
        ) : null}
      </dialog>
    </>
  );
}
