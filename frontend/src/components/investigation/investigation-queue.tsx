"use client";

import { type FormEvent, useState, useSyncExternalStore } from "react";

import { ApiClientError, type CaseOverview, type InvestigationSummary } from "@/lib/api";
import { browserApi } from "@/lib/api/browser-api";
import { formatDateTime } from "@/lib/presentation/formatters";

import { CaseNavigation } from "@/components/case/case-navigation";
import { IntegrityBadge } from "@/components/ui/integrity-badge";

import { InvestigationTimeline } from "./investigation-timeline";

import styles from "./investigation-queue.module.css";

interface InvestigationQueueProps {
  readonly caseOverview: CaseOverview;
}

function presentInvestigationError(error: unknown): string {
  if (error instanceof ApiClientError && error.code === "OLLAMA_UNAVAILABLE") {
    return "El investigador local no está disponible. El resultado autoritativo y el sello del caso permanecen sin cambios.";
  }

  if (error instanceof ApiClientError && error.code === "POLICY_REJECTED") {
    return "La política rechazó la propuesta; no se ejecutó ninguna herramienta. Reformulá la pregunta dentro del alcance del caso.";
  }

  if (error instanceof ApiClientError && error.code === "INVALID_REQUEST") {
    return "La pregunta no cumple el contrato de investigación. Revisá el texto y volvé a intentarlo.";
  }

  return "No se pudo confirmar el resultado de la solicitud. Actualizá la página antes de asumir que la propuesta o una observación fueron registradas.";
}

function subscribeToHydration() {
  return () => undefined;
}

function getClientHydrationSnapshot() {
  return true;
}

function getServerHydrationSnapshot() {
  return false;
}

export function InvestigationQueue({ caseOverview }: InvestigationQueueProps) {
  const { authoritative_result: result, case_id: caseId, seal } = caseOverview;
  const [investigation, setInvestigation] = useState<InvestigationSummary>(caseOverview.investigation);
  const isReady = useSyncExternalStore(subscribeToHydration, getClientHydrationSnapshot, getServerHydrationSnapshot);
  const [question, setQuestion] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const hasObservation = investigation.observations.length > 0;

  async function submitProposal(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const submittedQuestion = String(new FormData(event.currentTarget).get("question") ?? "").trim();

    if (!submittedQuestion || isSubmitting) {
      return;
    }

    setError(null);
    setNotice(null);
    setIsSubmitting(true);

    try {
      const proposal = await browserApi.proposeInvestigation(caseId, { question: submittedQuestion });
      const updatedInvestigation = await browserApi.getInvestigationSession(caseId);

      if (!updatedInvestigation.proposals.some(({ proposal_id }) => proposal_id === proposal.proposal_id)) {
        setError(
          "La propuesta fue aceptada, pero la sesión devuelta no permite confirmar su registro. Actualizá la página antes de continuar.",
        );
        return;
      }

      setInvestigation(updatedInvestigation);
      setQuestion("");
      setNotice("La secuencia de investigación se actualizó desde el servicio local.");
    } catch (submissionError) {
      setError(presentInvestigationError(submissionError));
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className={styles.workspace}>
      <header className={styles.header}>
        <div>
          <p className={styles.eyebrow}>Cola de investigación</p>
          <h1>{caseId}</h1>
          <p>Secuencia read-only separada del análisis determinista y del resultado sellado.</p>
        </div>
        <IntegrityBadge label="Sello vigente" status={seal.status} />
      </header>

      <CaseNavigation activeView="investigation" caseId={caseId} />

      <section aria-label="Límite de autoridad" className={styles.authorityBoundary}>
        <div>
          <span>Propuesta</span>
          <strong>No es un hallazgo</strong>
        </div>
        <div>
          <span>Observación</span>
          <strong>No es un veredicto</strong>
        </div>
        <div>
          <span>Modelo local</span>
          <strong>No es autoridad</strong>
        </div>
      </section>

      <section aria-labelledby="proposal-title" className={styles.proposalComposer}>
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>Nueva propuesta</p>
          <h2 id="proposal-title">Solicitá una investigación adicional</h2>
          <p>
            El investigador local decide la herramienta dentro de su allowlist; la política determina si puede
            ejecutarse. La propuesta y cualquier observación no modifican el resultado sellado.
          </p>
        </div>
        <form onSubmit={submitProposal}>
          <label htmlFor="investigation-question">Pregunta para el investigador local</label>
          <textarea
            aria-describedby={
              error
                ? "investigation-question-hint investigation-question-error"
                : "investigation-question-hint"
            }
            disabled={!isReady || isSubmitting}
            id="investigation-question"
            maxLength={500}
            name="question"
            onChange={(event) => {
              setQuestion(event.target.value);
              setError(null);
            }}
            placeholder="¿Qué información adicional debería revisarse sobre este caso?"
            required
            rows={4}
            value={question}
          />
          <p id="investigation-question-hint">
            La pregunta se envía al investigador local; no puede establecer hallazgos, veredictos ni sellos.
          </p>
          <button disabled={!isReady || isSubmitting} type="submit">
            {isSubmitting ? "Enviando propuesta…" : "Solicitar investigación"}
          </button>
        </form>
        {!isReady ? <p className={styles.submissionNotice} role="status">Preparando el envío seguro…</p> : null}
        <noscript>
          <p className={styles.submissionError}>
            Esta operación requiere JavaScript para enviar una solicitud JSON al policy gate local.
          </p>
        </noscript>
        {notice ? <p className={styles.submissionNotice} role="status">{notice}</p> : null}
        {error ? <p className={styles.submissionError} id="investigation-question-error" role="alert">{error}</p> : null}
      </section>

      <section aria-labelledby="investigation-status-title" className={styles.resultState}>
        <div>
          <p className={styles.eyebrow}>Estado de la sesión</p>
          <h2 id="investigation-status-title">{investigation.status}</h2>
          <p>Sesión: {investigation.session_id ?? "No iniciada"}</p>
        </div>
        <div className={styles.resultStateLabels}>
          {hasObservation ? <strong>OBSERVATION_RECORDED</strong> : <strong>NO_OBSERVATION_RECORDED</strong>}
          <strong>
            {investigation.authoritative_result_unchanged
              ? "AUTHORITATIVE_RESULT_UNCHANGED"
              : "AUTHORITATIVE_RESULT_UPDATE_NOT_SUPPLIED"}
          </strong>
        </div>
        <p>
          Resultado vigente: {result.verdict}. Último sello verificado: {formatDateTime(caseOverview.audit.checked_at)}.
        </p>
      </section>

      <section aria-labelledby="timeline-title" className={styles.section}>
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>Propuesta → policy → herramienta → observación</p>
          <h2 id="timeline-title">Secuencia registrada</h2>
        </div>
        <InvestigationTimeline investigation={investigation} />
      </section>
    </div>
  );
}
