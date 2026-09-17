import type { InvestigationProposal, InvestigationSummary, Observation } from "@/lib/api";
import { formatDateTime, formatHash } from "@/lib/presentation/formatters";

import { InvestigationStatusBadge } from "./investigation-status-badge";

import styles from "./investigation-timeline.module.css";

interface InvestigationTimelineProps {
  readonly investigation: InvestigationSummary;
}

const policyGateMessages: Record<InvestigationProposal["status"], string> = {
  APPROVED: "La política aprobó la propuesta; la ejecución todavía no está registrada.",
  EXECUTED: "La política aprobó la propuesta y la herramienta read-only fue ejecutada.",
  PROPOSED: "La propuesta espera evaluación de política y capability.",
  REJECTED: "La política rechazó la propuesta; no se ejecutó ninguna herramienta.",
};

function ProposalCard({ proposal }: { readonly proposal: InvestigationProposal }) {
  return (
    <article className={styles.proposal}>
      <header className={styles.itemHeader}>
        <div>
          <p className={styles.itemKind}>Propuesta</p>
          <h3>{proposal.proposal_id}</h3>
        </div>
        <InvestigationStatusBadge status={proposal.status} />
      </header>
      <dl className={styles.definitionList}>
        <div>
          <dt>Pregunta</dt>
          <dd>{proposal.question}</dd>
        </div>
        <div>
          <dt>Rationale</dt>
          <dd>{proposal.rationale}</dd>
        </div>
        <div>
          <dt>Información buscada</dt>
          <dd>{proposal.information_sought}</dd>
        </div>
      </dl>
      <div className={styles.technicalGrid}>
        <dl>
          <div>
            <dt>Herramienta solicitada</dt>
            <dd>{proposal.requested_tool}</dd>
          </div>
          <div>
            <dt>Capability</dt>
            <dd>{proposal.capability}</dd>
          </div>
        </dl>
        <dl>
          <div>
            <dt>Digest de argumentos</dt>
            <dd>{formatHash(proposal.arguments_digest)}</dd>
          </div>
          <div>
            <dt>Registrada</dt>
            <dd>{formatDateTime(proposal.created_at)}</dd>
          </div>
        </dl>
      </div>
      <p className={styles.policyGate}>
        <strong>Policy gate:</strong> {policyGateMessages[proposal.status]}
      </p>
    </article>
  );
}

function ObservationCard({ observation }: { readonly observation: Observation }) {
  const payload = observation.payload ? JSON.stringify(observation.payload, null, 2) : "Sin payload disponible.";

  return (
    <article className={styles.observation}>
      <header className={styles.itemHeader}>
        <div>
          <p className={styles.itemKind}>Observación</p>
          <h3>{observation.observation_id}</h3>
        </div>
        <InvestigationStatusBadge status={observation.status} />
      </header>
      <dl className={styles.technicalGrid}>
        <div>
          <dt>Propuesta de origen</dt>
          <dd>{observation.proposal_id}</dd>
        </div>
        <div>
          <dt>Herramienta</dt>
          <dd>{observation.tool_name}</dd>
        </div>
        <div>
          <dt>Capability</dt>
          <dd>{observation.capability}</dd>
        </div>
        <div>
          <dt>Digest de argumentos</dt>
          <dd>{formatHash(observation.arguments_digest)}</dd>
        </div>
        <div>
          <dt>Hash de payload</dt>
          <dd>{formatHash(observation.payload_sha256)}</dd>
        </div>
        <div>
          <dt>Registrada</dt>
          <dd>{formatDateTime(observation.recorded_at)}</dd>
        </div>
      </dl>
      <div className={styles.payload}>
        <h4>Payload registrado</h4>
        <pre>{payload}</pre>
      </div>
      <p className={styles.observationNotice}>
        Una observación es un dato de herramienta. No es evidencia autoritativa ni modifica el veredicto.
      </p>
    </article>
  );
}

export function InvestigationTimeline({ investigation }: InvestigationTimelineProps) {
  const observationsByProposal = new Map<string, Observation[]>();

  for (const observation of investigation.observations) {
    const observations = observationsByProposal.get(observation.proposal_id) ?? [];
    observations.push(observation);
    observationsByProposal.set(observation.proposal_id, observations);
  }

  const proposalIds = new Set(investigation.proposals.map((proposal) => proposal.proposal_id));
  const orphanObservations = investigation.observations.filter(
    (observation) => !proposalIds.has(observation.proposal_id),
  );

  if (investigation.proposals.length === 0) {
    return <p className={styles.emptyState}>No hay propuestas registradas para esta sesión de investigación.</p>;
  }

  return (
    <ol aria-label="Secuencia de investigación" className={styles.timeline} role="list">
      {investigation.proposals.map((proposal) => (
        <li key={proposal.proposal_id}>
          <ProposalCard proposal={proposal} />
          {observationsByProposal.get(proposal.proposal_id)?.map((observation) => (
            <ObservationCard key={observation.observation_id} observation={observation} />
          ))}
        </li>
      ))}
      {orphanObservations.map((observation) => (
        <li key={observation.observation_id}>
          <ObservationCard observation={observation} />
        </li>
      ))}
    </ol>
  );
}
