"use client";

import Link from "next/link";
import { type FormEvent, type KeyboardEvent, useState } from "react";

import { IntegrityBadge } from "@/components/ui/integrity-badge";
import { VerdictPill } from "@/components/ui/verdict-pill";
import { api } from "@/lib/api";
import type { EvidenceRef, NarrativeAnswer, Verdict, VerificationStatus } from "@/lib/api";

import { presentNarrationError, type NarrationErrorPresentation } from "./narration-error";

import styles from "./junior-chat.module.css";

const suggestedQuestions = [
  "¿Qué pasó?",
  "¿Por qué el sistema sospecha?",
  "¿Qué evidencia lo sostiene?",
  "¿Qué todavía no sabemos?",
  "¿Qué debería mirar después?",
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
    return <p className={styles.emptyCitation}>Esta respuesta no incorpora referencias de evidencia adicionales.</p>;
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
    <article aria-label="Respuesta narrativa verificada" className={styles.answer}>
      <header className={styles.answerHeader}>
        <span className={styles.answerLabel}>Narración sobre paquete sellado</span>
        <span className={styles.certainty} data-certainty={answer.certainty}>
          Certeza: {answer.certainty}
        </span>
      </header>
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
    </article>
  );
}

export function JuniorChat({ caseId, sealStatus, verdict }: JuniorChatProps) {
  const [messages, setMessages] = useState<readonly ChatMessage[]>([]);
  const [question, setQuestion] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<NarrationErrorPresentation | null>(null);
  const [status, setStatus] = useState("");

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
      const answer = await api.explain(caseId, submittedQuestion);
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
      <header className={styles.header}>
        <div>
          <p className={styles.eyebrow}>Explicación para análisis inicial</p>
          <h1>Consultá el caso sin alterar su resultado</h1>
          <p>
            Las respuestas se limitan al paquete autoritativo sellado. No incluyen razonamiento interno
            del modelo ni hechos no verificados.
          </p>
        </div>
        <div aria-label="Estado autoritativo del caso" className={styles.caseStatus}>
          <span className={styles.caseId}>{caseId}</span>
          <VerdictPill verdict={verdict} />
          <IntegrityBadge label="Sello" status={sealStatus} />
        </div>
      </header>

      <aside className={styles.authorityNotice}>
        <strong>La explicación no modifica el veredicto autoritativo.</strong>
        <span>La evidencia congelada y el motor determinista conservan la autoridad.</span>
      </aside>

      <section aria-labelledby="suggested-questions-title" className={styles.suggestions}>
        <div>
          <p className={styles.eyebrow}>Preguntas permitidas</p>
          <h2 id="suggested-questions-title">Empezá con una pregunta sobre el resultado</h2>
        </div>
        <div className={styles.suggestionList}>
          {suggestedQuestions.map((suggestedQuestion) => (
            <button
              disabled={isSending}
              key={suggestedQuestion}
              onClick={() => void sendQuestion(suggestedQuestion)}
              type="button"
            >
              {suggestedQuestion}
            </button>
          ))}
        </div>
      </section>

      <section aria-labelledby="conversation-title" className={styles.conversation}>
        <div className={styles.conversationHeading}>
          <div>
            <p className={styles.eyebrow}>Conversación</p>
            <h2 id="conversation-title">Respuestas con fuentes</h2>
          </div>
          <Link href={`/cases/${caseId}/evidence`}>Abrir evidencia</Link>
        </div>

        {messages.length === 0 ? (
          <p className={styles.emptyThread}>
            Elegí una pregunta sugerida o escribí una consulta acotada al resultado sellado.
          </p>
        ) : (
          <ol className={styles.messageList}>
            {messages.map((message) => (
              <li key={message.id}>
                {message.kind === "question" ? (
                  <article className={styles.question}>
                    <span>Tu consulta</span>
                    <p>{message.value}</p>
                  </article>
                ) : (
                  <AssistantAnswer answer={message.value} caseId={caseId} messageId={message.id} />
                )}
              </li>
            ))}
          </ol>
        )}

        {isSending ? <p className={styles.pending}>Consultando el paquete sellado…</p> : null}
        {status ? <p aria-live="polite" className="visually-hidden">{status}</p> : null}
        {error ? (
          <section aria-labelledby="narration-error-title" className={styles.error} role="alert">
            <h3 id="narration-error-title">{error.title}</h3>
            <p>{error.detail}</p>
          </section>
        ) : null}
      </section>

      <form className={styles.composer} onSubmit={handleSubmit}>
        <label htmlFor="junior-question">Pregunta sobre el caso</label>
        <p id="junior-question-hint">
          Usá las preguntas sugeridas o consultá exclusivamente sobre evidencia, hallazgos e incertidumbres selladas.
        </p>
        <textarea
          aria-describedby="junior-question-hint"
          disabled={isSending}
          enterKeyHint="send"
          id="junior-question"
          maxLength={500}
          name="question"
          onChange={(event) => setQuestion(event.target.value)}
          onKeyDown={handleComposerKeyDown}
          placeholder="Escribí una pregunta sobre el caso"
          required
          rows={3}
          value={question}
        />
        <div className={styles.composerFooter}>
          <span>Enter para enviar · Shift + Enter para una nueva línea</span>
          <button disabled={isSending} type="submit">
            {isSending ? "Consultando…" : "Consultar paquete sellado"}
          </button>
        </div>
      </form>
    </div>
  );
}
