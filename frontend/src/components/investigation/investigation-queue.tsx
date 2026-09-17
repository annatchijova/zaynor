"use client";

import { type FormEvent, useState } from "react";

import type { CaseOverview, InvestigationSummary } from "@/lib/api";
import { api } from "@/lib/api";
import { ApiClientError } from "@/lib/api";
import { formatDateTime } from "@/lib/presentation/formatters";

import { CaseNavigation } from "@/components/case/case-navigation";
import { IntegrityBadge } from "@/components/ui/integrity-badge";

import { InvestigationTimeline } from "./investigation-timeline";

import styles from "./investigation-queue.module.css";

interface InvestigationQueueProps {
  readonly caseOverview: CaseOverview;
}

export function InvestigationQueue({ caseOverview }: InvestigationQueueProps) {
  const { authoritative_result: result, case_id: caseId, seal } = caseOverview;
  const [investigation, setInvestigation] = useState<InvestigationSummary>(caseOverview.investigation);
  const [question, setQuestion] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const hasObservation = investigation.observations.length > 0;

  async function submitQuestion(rawQuestion: string) {
    const submittedQuestion = rawQuestion.trim();

    if (!submittedQuestion || isSubmitting) {
      return;
    }

    setError(null);
    setIsSubmitting(true);

    try {
      // The LLM proposes which read-only tool to call and with what
      // arguments -- a human does not pick them here. `proposeInvestigation`
      // only returns the proposal itself; re-fetching the session picks up
      // the observation it recorded in the same request (the tool call is
      // synchronous and deterministic, not queued).
      await api.proposeInvestigation(caseId, { question: submittedQuestion });
      const refreshed = await api.getInvestigationSession(caseId);
      setInvestigation(refreshed);
      setQuestion("");
    } catch (requestError) {
      setError(
        requestError instanceof ApiClientError
          ? requestError.message
          : "No se pudo registrar la propuesta. Intentá de nuevo.",
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void submitQuestion(question);
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

      <section aria-labelledby="composer-title" className={styles.section}>
        <div className={styles.sectionHeading}>
          <p className={styles.eyebrow}>Proponer una pregunta</p>
          <h2 id="composer-title">Qué investigar después</h2>
        </div>
        <p className={styles.composerHint}>
          El modelo local propone una única pregunta acotada; una política determinista decide si la
          herramienta read-only solicitada está permitida para este rol antes de que se ejecute algo. Vos no
          elegís la herramienta ni sus argumentos — eso lo decide el modelo, dentro de los límites de su
          contrato.
        </p>
        <form className={styles.composer} onSubmit={handleSubmit}>
          <label className="visually-hidden" htmlFor="investigation-question">
            Qué investigar después
          </label>
          <textarea
            disabled={isSubmitting}
            id="investigation-question"
            maxLength={500}
            name="question"
            onChange={(event) => setQuestion(event.target.value)}
            placeholder="¿Qué convendría investigar a continuación?"
            required
            rows={2}
            value={question}
          />
          <button disabled={isSubmitting || !question.trim()} type="submit">
            {isSubmitting ? "Proponiendo…" : "Proponer"}
          </button>
        </form>
        {error ? (
          <p className={styles.composerError} role="alert">
            {error}
          </p>
        ) : null}
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
