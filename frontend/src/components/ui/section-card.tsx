import type { ReactNode } from "react";

interface SectionCardProps {
  readonly children: ReactNode;
  readonly className?: string;
}

export function SectionCard({ children, className }: SectionCardProps) {
  return <section className={["section-card", className].filter(Boolean).join(" ")}>{children}</section>;
}
