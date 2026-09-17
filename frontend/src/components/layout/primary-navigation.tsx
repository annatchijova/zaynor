"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const caseId = "CASE-001";

const navigation = [
  { href: "/", label: "Inicio" },
  { href: "/about", label: "Acerca de" },
  { href: `/cases/${caseId}`, label: "Caso" },
  { href: `/cases/${caseId}/evidence`, label: "Evidencia" },
  { href: `/cases/${caseId}/audit`, label: "Auditoría" },
  { href: `/cases/${caseId}/chat`, label: "Asistencia" },
  { href: `/cases/${caseId}/senior`, label: "Senior" },
  { href: `/cases/${caseId}/investigation`, label: "Investigación" },
  { href: `/architecture`, label: "Arquitectura" },
] as const;

function isCurrentPath(pathname: string, href: string) {
  return href === "/" ? pathname === href : pathname === href;
}

interface NavigationLinksProps {
  readonly pathname?: string;
}

function NavigationLinks({ pathname }: NavigationLinksProps) {

  return (
    <nav aria-label="Principal" className="primary-navigation">
      <ul>
        {navigation.map(({ href, label }) => {
          const isCurrent = pathname ? isCurrentPath(pathname, href) : false;

          return (
            <li key={href}>
              <Link aria-current={isCurrent ? "page" : undefined} href={href}>
                {label}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

export function PrimaryNavigation() {
  return <NavigationLinks pathname={usePathname()} />;
}

export function PrimaryNavigationFallback() {
  return <NavigationLinks />;
}
