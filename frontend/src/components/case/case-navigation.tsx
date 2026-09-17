import Link from "next/link";

interface CaseNavigationProps {
  readonly activeView: "audit" | "chat" | "evidence" | "investigation" | "overview" | "reports" | "senior";
  readonly caseId: string;
}

const views = [
  { key: "overview", label: "Resultado", suffix: "" },
  { key: "evidence", label: "Evidencia", suffix: "/evidence" },
  { key: "audit", label: "Auditoría", suffix: "/audit" },
  { key: "chat", label: "Junior", suffix: "/chat" },
  { key: "senior", label: "Senior", suffix: "/senior" },
  { key: "investigation", label: "Investigación", suffix: "/investigation" },
  { key: "reports", label: "Reportes", suffix: "/reports" },
] as const;

export function CaseNavigation({ activeView, caseId }: CaseNavigationProps) {
  return (
    <nav aria-label="Caso" className="case-navigation">
      <ul>
        {views.map(({ key, label, suffix }) => (
          <li key={key}>
            <Link
              aria-current={key === activeView ? "page" : undefined}
              href={`/cases/${caseId}${suffix}`}
            >
              {label}
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  );
}
