import type { Verdict } from "@/lib/api/contracts";

const verdictText: Record<Verdict, string> = {
  MALICE: "Malice",
  SUSPICION: "Suspicion",
  ABSTAIN: "Abstain",
  UNKNOWN: "Unknown",
  BENIGN: "Benign",
};

interface VerdictPillProps {
  readonly verdict: Verdict;
}

export function VerdictPill({ verdict }: VerdictPillProps) {
  return (
    <span className="verdict-pill" data-verdict={verdict}>
      <span aria-hidden="true" className="verdict-pill__indicator" />
      <span>{verdictText[verdict]}</span>
    </span>
  );
}
