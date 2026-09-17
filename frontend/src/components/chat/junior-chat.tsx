"use client";

import Link from "next/link";
import { type FormEvent, type KeyboardEvent, useEffect, useRef, useState } from "react";

import { IntegrityBadge } from "@/components/ui/integrity-badge";
import { VerdictPill } from "@/components/ui/verdict-pill";
import { browserApi } from "@/lib/api/browser-api";
import type { EvidenceRef, NarrativeAnswer, Verdict, VerificationStatus } from "@/lib/api";

import { presentNarrationError, type NarrationErrorPresentation } from "./narration-error";

import styles from "./junior-chat.module.css";

const suggestedQuestions = [
  "¿Qué encontró el motor y con qué evidencia lo sostiene?",
  "¿Por qué el sistema llegó a este veredicto?",
  "¿Qué preguntas todavía quedan sin responder?",
  "¿Qué debería revisar primero como analista junior?",
  "¿Este resultado podría cambiar con más evidencia?",
] as const;

interface AnswerMessage {
  readonly id: string;
  readonly kind: "answer";
  readonly value: NarrativeAnswer;
}

interface QuestionMessage {
  readonly id: string;
  readonly kind: "question";
  readonly value: string;
}

type ChatMessage = AnswerMessage | QuestionMessage;

interface JuniorChatProps {
  readonly caseId: string;
  readonly sealStatus: VerificationStatus;
  readonly verdict: Verdict;
}

function EvidenceCitations({ caseId, references }: { readonly caseId: string; readonly references: readonly EvidenceRef[] }) {
  if (references.length === 0) {
    return <p className={styles.emptyCitation}>Sin referencias de evidencia adicionales.</p>;
  }

  return (
    <ul className={styles.citationList}>
      {references.map((reference) => (
        <li key={`${reference.artifact}-${reference.lineage_id}`}>
          <Link href={`/cases/${caseId}/evidence`}>{reference.artifact}</Link>
          <span>Linaje: {reference.lineage_id}</span>
        </li>
      ))}
    </ul>
  );
}

function AssistantAnswer({
  answer,
  caseId,
  messageId,
}: {
  readonly answer: NarrativeAnswer;
  readonly caseId: string;
  readonly messageId: string;
}) {
  const findingRefsId = `finding-refs-${messageId}`;
  const evidenceRefsId = `evidence-refs-${messageId}`;

  return (
    <div aria-label="Respuesta narrativa verificada">
      <div className={styles.answerHead}>
        <span className={styles.certainty} data-certainty={answer.certainty}>
          Certeza: {answer.certainty}
        </span>
      </div>
      <p className={styles.narrative}>{answer.narrative}</p>
      <div className={styles.citations}>
        <section aria-labelledby={findingRefsId}>
          <h3 id={findingRefsId}>Hallazgos citados</h3>
          {answer.finding_refs.length > 0 ? (
            <ul className={styles.referenceTokens}>
              {answer.finding_refs.map((reference) => (
                <li key={reference}>{reference}</li>
              ))}
            </ul>
          ) : (
            <p className={styles.emptyCitation}>No se citan hallazgos adicionales.</p>
          )}
        </section>
        <section aria-labelledby={evidenceRefsId}>
          <h3 id={evidenceRefsId}>Evidencia citada</h3>
          <EvidenceCitations caseId={caseId} references={answer.evidence_refs} />
        </section>
      </div>
      <p className={styles.answerDisclaimer}>{answer.disclaimer}</p>
    </div>
  );
}

export function JuniorChat({ caseId, sealStatus, verdict }: JuniorChatProps) {
  const [messages, setMessages] = useState<readonly ChatMessage[]>([]);
  const [question, setQuestion] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<NarrationErrorPresentation | null>(null);
  const [status, setStatus] = useState("");
  const threadRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const node = threadRef.current;
    if (node) {
      node.scrollTop = node.scrollHeight;
    }
  }, [messages, isSending, error]);

  async function sendQuestion(rawQuestion: string) {
    const submittedQuestion = rawQuestion.trim();

    if (!submittedQuestion || isSending) {
      return;
    }

    setError(null);
    setStatus("");
    setIsSending(true);
    setQuestion("");
    setMessages((currentMessages) => [
      ...currentMessages,
      { id: `question-${crypto.randomUUID()}`, kind: "question", value: submittedQuestion },
    ]);

    try {
      const answer = await browserApi.explain(caseId, submittedQuestion);
      setMessages((currentMessages) => [
        ...currentMessages,
        { id: `answer-${crypto.randomUUID()}`, kind: "answer", value: answer },
      ]);
      setStatus("Respuesta basada en el paquete sellado disponible.");
    } catch (requestError) {
      setError(presentNarrationError(requestError));
    } finally {
      setIsSending(false);
    }
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void sendQuestion(question);
  }

  function handleComposerKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key !== "Enter" || event.shiftKey) {
      return;
    }

    if (event.nativeEvent.isComposing || event.nativeEvent.keyCode === 229) {
      return;
    }

    event.preventDefault();
    void sendQuestion(question);
  }

  return (
    <div className={styles.chat}>
      <div className={styles.console}>
        <header className={styles.consoleHeader}>
          <div>
            <span className={styles.eyebrow}>Consola junior</span>
            <h1>
              Consultá el caso <span className={styles.thin}>— sin alterar su resultado</span>
            </h1>
          </div>
          <div aria-label="Estado autoritativo del caso" className={styles.caseStatus}>
            <span className={styles.caseId}>{caseId}</span>
            <VerdictPill verdict={verdict} />
            <IntegrityBadge label="Sello" status={sealStatus} />
          </div>
        </header>

        <div className={styles.thread} ref={threadRef}>
          <div className={`${styles.msg} ${styles.mentor}`}>
            <span className={styles.who}>ZAYNOR</span>
            <div className={`${styles.bubble} ${styles.intro}`}>
              La explicación se limita al paquete autoritativo ya sellado. No incluye razonamiento interno
              del modelo ni hechos no verificados — lo que no se puede sostener contra el resultado se
              marca y se retira antes de mostrarse. No hay preguntas equivocadas.
            </div>
          </div>

          {messages.map((message) => (
            <div className={`${styles.msg} ${message.kind === "question" ? styles.user : styles.mentor}`} key={message.id}>
              <span className={styles.who}>{message.kind === "question" ? "Vos" : "ZAYNOR"}</span>
              <div className={styles.bubble}>
                {message.kind === "question" ? (
                  message.value
                ) : (
                  <AssistantAnswer answer={message.value} caseId={caseId} messageId={message.id} />
                )}
              </div>
            </div>
          ))}

          {isSending ? (
            <div className={`${styles.msg} ${styles.mentor}`}>
              <span className={styles.who}>ZAYNOR</span>
              <div className={`${styles.bubble} ${styles.thinking}`}>Consultando el paquete sellado…</div>
            </div>
          ) : null}

          {error ? (
            <div className={`${styles.msg} ${styles.mentor}`} role="alert">
              <span className={styles.who}>Error</span>
              <div className={`${styles.bubble} ${styles.errorBubble}`}>
                <strong>{error.title}</strong>
                <p>{error.detail}</p>
              </div>
            </div>
          ) : null}
        </div>

        {messages.length === 0 && !isSending ? (
          <div aria-label="Preguntas sugeridas" className={styles.chips}>
            {suggestedQuestions.map((suggestedQuestion) => (
              <button
                className={styles.chip}
                disabled={isSending}
                key={suggestedQuestion}
                onClick={() => void sendQuestion(suggestedQuestion)}
                type="button"
              >
                {suggestedQuestion}
              </button>
            ))}
          </div>
        ) : null}

        <form className={styles.composer} onSubmit={handleSubmit}>
          <label className="visually-hidden" htmlFor="junior-question">
            Pregunta sobre el caso
          </label>
          <textarea
            aria-describedby="junior-question-hint"
            disabled={isSending}
            enterKeyHint="send"
            id="junior-question"
            maxLength={500}
            name="question"
            onChange={(event) => setQuestion(event.target.value)}
            onKeyDown={handleComposerKeyDown}
            placeholder="Preguntale al caso…"
            required
            rows={1}
            value={question}
          />
          <button disabled={isSending} type="submit">
            {isSending ? "Consultando…" : "Enviar"}
          </button>
        </form>
        <p className="visually-hidden" id="junior-question-hint">
          Enter para enviar, Shift + Enter para una nueva línea. Máximo 500 caracteres.
        </p>
      </div>

      <p className={styles.footNote}>
        ZAYNOR narra a partir de un resultado ya sellado; nunca decide el veredicto.{" "}
        <Link href={`/cases/${caseId}/evidence`}>Abrir evidencia</Link>
      </p>
      {status ? (
        <p aria-live="polite" className="visually-hidden">
          {status}
        </p>
      ) : null}
    </div>
  );
}
