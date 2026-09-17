import type { ObservationStatus, ProposalStatus } from "@/lib/api";

type InvestigationStatus = ObservationStatus | ProposalStatus;

const labels: Record<InvestigationStatus, string> = {
  APPROVED: "Aprobada",
  EXECUTED: "Ejecutada",
  FAILED: "Fallida",
  OBSERVED: "Observación registrada",
  PROPOSED: "Propuesta registrada",
  REJECTED: "Rechazada",
  UNTRUSTED: "No confiable",
};

interface InvestigationStatusBadgeProps {
  readonly status: InvestigationStatus;
}

export function InvestigationStatusBadge({ status }: InvestigationStatusBadgeProps) {
  return (
    <span className="investigation-status-badge" data-status={status}>
      <span aria-hidden="true" className="investigation-status-badge__mark" />
      <span>{labels[status]}</span>
      <strong>{status}</strong>
    </span>
  );
}
