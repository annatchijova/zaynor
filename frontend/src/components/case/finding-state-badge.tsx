import type { FindingState } from "@/lib/api/contracts";

const labels: Record<FindingState, string> = {
  ABSTAIN: "Abstención",
  BENIGN: "Benigno",
  CONTRADICTED: "Refutado",
  CORROBORATED: "Corroborado",
  INSUFFICIENT: "Insuficiente",
  MALICE: "Malicia",
  SUSPICION: "Sospecha",
  UNKNOWN: "Desconocido",
};

interface FindingStateBadgeProps {
  readonly state: FindingState;
}

export function FindingStateBadge({ state }: FindingStateBadgeProps) {
  return (
    <span className="finding-state-badge" data-state={state}>
      {labels[state]}
    </span>
  );
}
