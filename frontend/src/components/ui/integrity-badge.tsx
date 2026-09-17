import type { VerificationStatus } from "@/lib/api/contracts";

const statusText: Record<VerificationStatus, string> = {
  VERIFIED: "Verified",
  FAILED: "Verification failed",
  UNKNOWN: "Not verified",
};

interface IntegrityBadgeProps {
  readonly label: string;
  readonly status: VerificationStatus;
}

export function IntegrityBadge({ label, status }: IntegrityBadgeProps) {
  return (
    <span className="integrity-badge" data-status={status}>
      <span aria-hidden="true" className="integrity-badge__mark" />
      <span>{label}</span>
      <strong>{statusText[status]}</strong>
    </span>
  );
}
