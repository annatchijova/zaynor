import type { ReactNode } from "react";

type StateTone = "empty" | "error" | "loading";

interface StatePanelProps {
  readonly action?: ReactNode;
  readonly detail: string;
  readonly title: string;
  readonly tone: StateTone;
}

export function StatePanel({ action, detail, title, tone }: StatePanelProps) {
  return (
    <section aria-labelledby={`state-${tone}-title`} className="state-panel" data-tone={tone}>
      {tone === "loading" ? <span aria-hidden="true" className="state-panel__spinner" /> : null}
      <div>
        <h2 id={`state-${tone}-title`}>{title}</h2>
        <p>{detail}</p>
        {action ? <div className="state-panel__action">{action}</div> : null}
      </div>
    </section>
  );
}
